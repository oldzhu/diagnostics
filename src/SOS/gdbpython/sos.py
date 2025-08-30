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

SOS_LIB_PATH = "/workspaces/diagnostics/artifacts/bin/linux.x64.Debug/libsos.so"

# --- GDB Command Class ---

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
            gdb.write("Please build the 'libsos' project and check the SOS_LIB_PATH in sos.py.\n")
            return False

        try:
            if TRACE_ENABLED:
                gdb.write("[sos] Loading libsos.so...\n")
            SOSCommand.sos_handle = ctypes.CDLL(SOS_LIB_PATH)
            if TRACE_ENABLED:
                gdb.write("[sos] Creating GdbServices...\n")
            SOSCommand.gdb_services = GdbServices()

            # Initialize the SOS library
            if TRACE_ENABLED:
                gdb.write("[sos] Resolving SOSInitializeByHost...\n")
            init_func = SOSCommand.sos_handle.SOSInitializeByHost
            if TRACE_ENABLED:
                gdb.write("[sos] Calling SOSInitializeByHost(NULL, IDebuggerServices) ...\n")
            
            # Correctly define the function signature with two PVOID input parameters
            # SOSInitializeByHost(IUnknown* punk, IDebuggerServices* debuggerServices)
            init_func.argtypes = [PVOID, PVOID]
            init_func.restype = HRESULT
            
            # Pass NULL for IHost so SOS uses its internal Host/Target; still pass our IDebuggerServices
            hr = init_func(ctypes.c_void_p(0), ctypes.byref(SOSCommand.gdb_services.idebugger_ptr))
            
            if hr != 0:
                gdb.write(f"SOSInitializeByHost failed with HRESULT {hr}.\n")
                SOSCommand.sos_handle = None
                return False
            
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
            # Resolve the exported SOS symbol for this command
            def to_export_candidates(cmd: str):
                manual = {
                    "dumpobj": "DumpObj",
                    "clrstack": "ClrStack",
                    "dso": "DumpStackObjects",
                }
                candidates = []
                # Manual mapping first
                if cmd in manual:
                    candidates.append(manual[cmd])
                # TitleCase (clrstack -> ClrStack)
                # Special-case common concatenations: clrstack -> ClrStack, dumpheap -> DumpHeap, gcroot -> GcRoot
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
                # Simple capitalize (dumpobj -> Dumpobj)
                cap = cmd.capitalize()
                if cap not in candidates:
                    candidates.append(cap)
                # Original name last
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

            # Execute the SOS command using the main GdbServices pointer
            # FEATURE_PAL DECLARE_API expects PDEBUG_CLIENT which is ILLDBServices*
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

# --- Register Commands ---
# To add more commands, just add a new line here.
DumpObjCommand = SOSCommand("dumpobj")
ClrStackCommand = SOSCommand("clrstack")
DsoCommand = SOSCommand("dso")

# Register the sostrace command from tracing module
SOSTraceCommand()