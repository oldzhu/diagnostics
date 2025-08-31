import gdb
import ctypes
import os
import sys
import re

# Ensure this directory is on sys.path for sibling module imports
_THIS_DIR = os.path.dirname(__file__)
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from abi import PVOID, PCSTR, HRESULT
from services import GdbServices
from tracing import TRACE_ENABLED, SOSTraceCommand

# Default build artifact locations; users can override via env vars
SOS_LIB_PATH = os.getenv("SOS_LIB_PATH", "/workspaces/diagnostics/artifacts/bin/linux.x64.Debug/libsos.so")
BRIDGE_LIB_PATH = os.getenv("SOS_BRIDGE_LIB_PATH", "/workspaces/diagnostics/artifacts/bin/linux.x64.Debug/libsosgdbbridge.so")

# Common HRESULT hints for nicer error messages
_HRES_HINTS = {
    0x80070057: "Invalid argument. Check command options.",
    0x80004001: "Not implemented for this target.",
    0x80004002: "Interface not supported (service unavailable).",
    0x80004003: "Invalid pointer (internal).",
    0x80004005: "Unspecified failure. Try 'sostrace on' for details.",
    0x8007000E: "Out of memory.",
    0x80070005: "Access denied or memory read failed.",
    0x800704C7: "Operation canceled.",
}

def _hint_for_hresult(hr: int) -> str:
    try:
        h = hr & 0xFFFFFFFF
    except Exception:
        h = hr
    return _HRES_HINTS.get(h, "")


class SOSCommand(gdb.Command):
    """A base class for SOS commands that handles loading libsos."""
    def __init__(self, name):
        super(SOSCommand, self).__init__(name, gdb.COMMAND_DATA)
        self.name = name
        SOSCommand.lazy_load_sos()

    @staticmethod
    def lazy_load_sos():
        """Loads and initializes libsos.so if not already loaded."""
        if not hasattr(SOSCommand, "sos_handle"):
            SOSCommand.sos_handle = None
        if SOSCommand.sos_handle:
            return True

        if not os.path.exists(SOS_LIB_PATH):
            gdb.write(f"Error: SOS library not found at '{SOS_LIB_PATH}'.\n")
            gdb.write("Please build the 'libsos' project and set SOS_LIB_PATH if needed.\n")
            return False

        try:
            if TRACE_ENABLED:
                gdb.write("[sos] Loading libsos.so...\n")
            SOSCommand.sos_handle = ctypes.CDLL(SOS_LIB_PATH)
            if TRACE_ENABLED:
                gdb.write("[sos] Creating GdbServices...\n")
            SOSCommand.gdb_services = GdbServices()

            # Prepare optional bridge (preferred) and libsos forwarders (fallback)
            SOSCommand.bridge_handle = None
            try:
                if os.path.exists(BRIDGE_LIB_PATH):
                    SOSCommand.bridge_handle = ctypes.CDLL(BRIDGE_LIB_PATH)
            except Exception:
                SOSCommand.bridge_handle = None
            # Optional libsos forwarders
            try:
                SOSCommand.sos_init_hosting = SOSCommand.sos_handle.SOS_InitManagedHosting
                SOSCommand.sos_init_hosting.argtypes = [ctypes.c_char_p, ctypes.c_int]
                SOSCommand.sos_init_hosting.restype = ctypes.c_int
            except Exception:
                SOSCommand.sos_init_hosting = None
            try:
                SOSCommand.sos_dispatch_managed = SOSCommand.sos_handle.SOS_DispatchManagedCommand
                SOSCommand.sos_dispatch_managed.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                SOSCommand.sos_dispatch_managed.restype = ctypes.c_int
            except Exception:
                SOSCommand.sos_dispatch_managed = None

            # Initialize the SOS library
            if TRACE_ENABLED:
                gdb.write("[sos] Resolving SOSInitializeByHost...\n")
            init_func = SOSCommand.sos_handle.SOSInitializeByHost
            if TRACE_ENABLED:
                gdb.write("[sos] Calling SOSInitializeByHost(NULL, IDebuggerServices) ...\n")

            # SOSInitializeByHost(IUnknown* punk, IDebuggerServices* debuggerServices)
            init_func.argtypes = [PVOID, PVOID]
            init_func.restype = HRESULT

            hr = init_func(ctypes.c_void_p(0), ctypes.byref(SOSCommand.gdb_services.idebugger_ptr))

            if hr != 0:
                gdb.write(f"SOSInitializeByHost failed with HRESULT {hr}.\n")
                SOSCommand.sos_handle = None
                return False

            # Initialize the bridge's Extensions singleton now; defer managed hosting
            try:
                if getattr(SOSCommand, 'bridge_handle', None):
                    # Initialize the bridge's Extensions singleton first
                    init_ext = getattr(SOSCommand.bridge_handle, 'InitGdbExtensions', None)
                    if init_ext is not None:
                        init_ext.argtypes = [ctypes.c_void_p]
                        init_ext.restype = ctypes.c_int
                        idebugger_ptr_addr = ctypes.addressof(SOSCommand.gdb_services.idebugger_ptr)
                        init_ext(ctypes.c_void_p(idebugger_ptr_addr))
                # Do not call InitManagedHosting here to avoid early managed assertion before target state is ready
            except Exception as e:
                if TRACE_ENABLED:
                    gdb.write(f"[sos] Bridge InitGdbExtensions note: {e}\n")

            gdb.write("SOS GDB Python extension loaded and initialized successfully.\n")
            return True
        except Exception as e:
            gdb.write(f"Error loading or initializing libsos.so: {e}\n")
            SOSCommand.sos_handle = None
            return False

    def invoke(self, arg, from_tty):
        if not SOSCommand.lazy_load_sos():
            return

        try:
            # Managed-only commands on Unix aren't native exports; try bridge managed dispatch first.
            managed_only = {
                "dso", "dumpstackobjects", "dumpheap", "verifyheap", "verifyobj", "gcroot",
                "gcwhere", "pathto", "dumpruntimetypes", "listnearobj", "objsize", "threadpool",
                "assemblies", "clrmodules", "loadsymbols", "setsymbolserver", "logging", "analyzeoom",
                "traverseheap"
            }
            # Common alias for managed help
            if self.name.lower() == "soshelp":
                managed_only.add("soshelp")
            if self.name.lower() in managed_only and sys.platform.startswith("linux"):
                # Prefer bridge managed dispatch; fall back to libsos forwarder
                cmd = self.name.lower().encode('utf-8')
                args = (arg or "").encode('utf-8')
                bridge = getattr(SOSCommand, 'bridge_handle', None)
                attempted = False
                hres_bridge = None
                hosting_initialized = False
                if bridge is not None:
                    try:
                        dispatch = bridge.DispatchManagedCommand
                        dispatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                        dispatch.restype = ctypes.c_int
                        hres_bridge = dispatch(cmd, args)
                        attempted = True
                        if TRACE_ENABLED:
                            gdb.write(f"[sos] Bridge DispatchManagedCommand('{self.name}') => 0x{hres_bridge:08x}\n")
                        if hres_bridge == 0:
                            return
                        # Check hosting status if bridge is present
                        try:
                            get_host = getattr(bridge, 'GetHostForSos', None)
                            if get_host is not None:
                                get_host.argtypes = []
                                get_host.restype = ctypes.c_void_p
                                hosting_initialized = bool(get_host())
                        except Exception:
                            pass
                    except Exception:
                        pass
                # Try libsos forwarder as a fallback
                hres_forwarder = None
                try:
                    if getattr(SOSCommand, 'sos_dispatch_managed', None):
                        hres_forwarder = SOSCommand.sos_dispatch_managed(cmd, args)
                        attempted = True or attempted
                        if hres_forwarder == 0:
                            return
                except Exception:
                    pass
                # Distinguish hosting-not-initialized vs command failure
                if hosting_initialized or (hres_bridge not in (None, 0)) or (hres_forwarder not in (None, 0)):
                    # Managed layer handled the call but returned a failure HRESULT
                    h = hres_bridge if hres_bridge not in (None, 0) else (hres_forwarder if hres_forwarder not in (None, 0) else 0)
                    if h:
                        h32 = h & 0xFFFFFFFF
                        hint = _hint_for_hresult(h32)
                        if hint:
                            gdb.write(f"Managed command '{self.name}' failed (HRESULT=0x{h32:08x}). {hint}\n")
                        else:
                            gdb.write(f"Managed command '{self.name}' failed (HRESULT=0x{h32:08x}).\n")
                    return
                # If we never managed to dispatch, print guidance
                gdb.write(
                    "This command is managed-only on Linux and isn’t exported from libsos.so.\n"
                    "Managed hosting is not initialized or failed.\n"
                    "Try: sethostruntime or use lldb’s sos plugin / dotnet-dump.\n"
                )
                return

            # Resolve the exported SOS symbol for this command
            def to_export_candidates(cmd: str):
                manual = {
                    "dumpobj": "DumpObj",
                    "clrstack": "ClrStack",
                    "dso": "DumpStackObjects",
                }
                candidates = []
                if cmd in manual:
                    candidates.append(manual[cmd])
                known_camel = {
                    "clrstack": "ClrStack",
                    "dumpheap": "DumpHeap",
                    "gcroot": "GcRoot",
                }
                if cmd in known_camel:
                    title = known_camel[cmd]
                else:
                    title = ''.join(part.capitalize() for part in re.split(r'[^0-9A-Za-z]+', cmd) if part)
                if title and title not in candidates:
                    candidates.append(title)
                cap = cmd.capitalize()
                if cap not in candidates:
                    candidates.append(cap)
                if cmd not in candidates:
                    candidates.append(cmd)
                return candidates

            sos_func = None
            tried = []
            for sym in to_export_candidates(self.name):
                tried.append(sym)
                try:
                    sos_func = getattr(SOSCommand.sos_handle, sym)
                    break
                except AttributeError:
                    continue
            if sos_func is None:
                gdb.write(f"Error: Command '{self.name}' not found in libsos.so (tried symbols: {', '.join(tried)}).\n")
                return
            sos_func.argtypes = [PVOID, PCSTR]
            sos_func.restype = HRESULT

            client_ptr = ctypes.byref(SOSCommand.gdb_services.illldb_ptr)
            if TRACE_ENABLED:
                gdb.write("[sos] Dispatching SOS command with ILLDBServices client\n")
            hr = sos_func(client_ptr, (arg or "").encode('utf-8'))
            if hr != 0:
                gdb.write(f"Command '{self.name}' failed with HRESULT {hr}.\n")

        except AttributeError:
            gdb.write(f"Error: Command '{self.name}' not found in libsos.so.\n")
        except Exception as e:
            gdb.write(f"An error occurred while executing '{self.name}': {e}\n")


# Register commands
DumpObjCommand = SOSCommand("dumpobj")
ClrStackCommand = SOSCommand("clrstack")
DsoCommand = SOSCommand("dso")
DumpHeapCommand = SOSCommand("dumpheap")
SosHelpCommand = SOSCommand("soshelp")

SOSTraceCommand()


class SetHostRuntimeCommand(gdb.Command):
    """Initialize SOS managed hosting. Usage: sethostruntime [-major N] [<runtime-directory>]"""
    def __init__(self):
        super(SetHostRuntimeCommand, self).__init__("sethostruntime", gdb.COMMAND_SUPPORT)

    def invoke(self, arg, from_tty):
    # Prefer libsos forwarder; fall back to bridge
        parts = arg.split() if arg else []
        major = 0
        runtime_dir = None
        i = 0
        while i < len(parts):
            if parts[i] == '-major' and i + 1 < len(parts):
                try:
                    major = int(parts[i + 1], 10)
                except Exception:
                    major = 0
                i += 2
            else:
                runtime_dir = parts[i]
                i += 1
        try:
            hres = None
            if getattr(SOSCommand, 'sos_init_hosting', None):
                hres = SOSCommand.sos_init_hosting(runtime_dir.encode('utf-8') if runtime_dir else None, int(major))
            elif getattr(SOSCommand, 'bridge_handle', None):
                init_hosting = SOSCommand.bridge_handle.InitManagedHosting
                init_hosting.argtypes = [ctypes.c_char_p, ctypes.c_int]
                init_hosting.restype = ctypes.c_int
                hres = init_hosting(runtime_dir.encode('utf-8') if runtime_dir else None, int(major))
            else:
                gdb.write("No hosting initializer available (libsos forwarder and bridge not found).\n")
                return
            if hres == 0:
                gdb.write("Managed hosting initialized.\n")
            else:
                gdb.write(f"InitManagedHosting failed HRESULT=0x{hres:08x}.\n")
        except Exception as e:
            gdb.write(f"Error initializing hosting: {e}\n")


SetHostRuntimeCommand()
