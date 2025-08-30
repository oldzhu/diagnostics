import gdb
import ctypes
import os
import sys
import re

# --- Configuration ---
# This needs to point to the location of your compiled libsos.so
# Adjust this path based on your build output directory.
SOS_LIB_PATH = "/workspaces/diagnostics/artifacts/bin/linux.x64.Debug/libsos.so"

# Trace control (off by default). Enable with env var SOS_PY_TRACE=1 or via the 'sostrace' GDB command.
def _parse_bool_env(val: str, default: bool = False) -> bool:
    if val is None:
        return default
    v = str(val).strip().lower()
    if v in ("1", "true", "yes", "on"): return True
    if v in ("0", "false", "no", "off"): return False
    return default

TRACE_ENABLED = _parse_bool_env(os.getenv("SOS_PY_TRACE"), False)

# --- Ctypes Definitions for SOS Interfaces ---
# These definitions must match the C++ headers (debuggerservices.h, pal.h)

# Basic types (match Windows-style widths on all platforms)
# HRESULT is 32-bit signed, ULONG is 32-bit unsigned, ULONG64 is 64-bit unsigned
HRESULT = ctypes.c_int32
ULONG = ctypes.c_uint32
ULONG64 = ctypes.c_uint64
PVOID = ctypes.c_void_p
CHAR = ctypes.c_char
PCSTR = ctypes.c_char_p

# GUID structure for QueryInterface (use fixed-width types; c_ulong is 64-bit on Linux)
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", (ctypes.c_ubyte * 8)),
    ]

# IIDs from debuggerservices.h
IID_IUnknown = GUID(0x00000000, 0x0000, 0x0000, (0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
IID_IMemoryService = GUID(0x84a8922E, 0x3C6C, 0x4499, (0x9B, 0x4A, 0x3A, 0x62, 0x24, 0x43, 0x5A, 0x79))
# IDebuggerServices IID from debuggerservices.h
IID_IDebuggerServices = GUID(0xB4640016, 0x6CA0, 0x468E, (0xBA, 0x2C, 0x1F, 0xFF, 0x28, 0xDE, 0x7B, 0x72))
# IHost IID from src/SOS/inc/host.h: E0CD8534-A88B-40D7-91BA-1B4C925761E9
IID_IHost = GUID(0xE0CD8534, 0xA88B, 0x40D7, (0x91, 0xBA, 0x1B, 0x4C, 0x92, 0x57, 0x61, 0xE9))
# ILLDBServices2 IID from src/SOS/inc/lldbservices.h
IID_ILLDBServices2 = GUID(0x012F32F0, 0x33BA, 0x4E8E, (0xBC, 0x01, 0x03, 0x7D, 0x38, 0x2D, 0x8A, 0x5E))
# ILLDBServices IID from src/SOS/inc/lldbservices.h
IID_ILLDBServices = GUID(0x2E6C569A, 0x9E14, 0x4DA4, (0x9D, 0xFC, 0xCD, 0xB7, 0x3A, 0x53, 0x25, 0x66))
# IHostServices IID from src/SOS/inc/hostservices.h
IID_IHostServices = GUID(0x27B2CB8D, 0xBDEE, 0x4CBD, (0xB6, 0xEF, 0x75, 0x88, 0x0D, 0x76, 0xD4, 0x6F))

# Constants needed for return values
DEBUG_CLASS_USER_WINDOWS = 2
DEBUG_DUMP_FULL = 1026
IMAGE_FILE_MACHINE_AMD64 = 0x8664
DEBUG_ANY_ID = 0xFFFFFFFF

# Function pointer types for the vtables
QI_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(GUID), ctypes.POINTER(PVOID))
ADDREF_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
RELEASE_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
READ_VIRTUAL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))
GET_OPERATING_SYSTEM_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ctypes.c_int))
DBG_GET_DEBUGGEE_TYPE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_PROCESSOR_TYPE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_ADD_COMMAND_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, PCSTR, ctypes.POINTER(PCSTR), ctypes.c_int)
DBG_OUTPUT_STRING_FUNC_TYPE = ctypes.CFUNCTYPE(None, PVOID, ULONG, PCSTR)
DBG_READ_VIRTUAL_FUNC_TYPE = READ_VIRTUAL_FUNC_TYPE
DBG_WRITE_VIRTUAL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))
DBG_GET_NUMBER_MODULES_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_MODULE_BY_INDEX_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))
DBG_GET_MODULE_NAMES_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))
DBG_GET_MODULE_INFO_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_MODULE_VERSION_INFO_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, PCSTR, PVOID, ULONG, ctypes.POINTER(ULONG))
DBG_GET_MODULE_BY_MODNAME_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))
DBG_GET_NUMBER_THREADS_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_GET_THREAD_IDS_BY_INDEX_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_THREAD_CONTEXT_BY_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, PVOID)
DBG_GET_CURRENT_PROCESS_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_GET_CURRENT_THREAD_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_SET_CURRENT_THREAD_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)
DBG_GET_THREAD_TEB_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))
DBG_VIRTUAL_UNWIND_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.c_uint32, PVOID)
DBG_GET_SYMBOL_PATH_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))
DBG_GET_SYMBOL_BY_OFFSET_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))
DBG_GET_OFFSET_BY_SYMBOL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ctypes.POINTER(ULONG64))
DBG_GET_TYPE_ID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ctypes.POINTER(ULONG64))
DBG_GET_FIELD_OFFSET_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG64, PCSTR, ctypes.POINTER(ULONG))
DBG_GET_OUTPUT_WIDTH_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
DBG_SUPPORTS_DML_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_OUTPUT_DML_STRING_FUNC_TYPE = ctypes.CFUNCTYPE(None, PVOID, ULONG, PCSTR)
DBG_ADD_MODULE_SYMBOL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, PCSTR)
DBG_GET_LAST_EVENT_INFO_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), PVOID, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))
DBG_FLUSH_CHECK_FUNC_TYPE = ctypes.CFUNCTYPE(None, PVOID)
DBG_EXECUTE_HOST_COMMAND_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, PVOID)
DBG_GET_DAC_SIG_VER_SETTINGS_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ctypes.c_int))
GET_HOST_TYPE_FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int, PVOID)
GET_SERVICE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(GUID), ctypes.POINTER(PVOID))
GET_CURRENT_TARGET_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(PVOID))

# IHostServices function pointer types
HOSTSERVICES_GETHOST = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(PVOID))
HOSTSERVICES_REGISTERDEBUGGER = ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)
HOSTSERVICES_CREATETARGET = ctypes.CFUNCTYPE(HRESULT, PVOID)
HOSTSERVICES_UPDATETARGET = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)
HOSTSERVICES_FLUSHTARGET = ctypes.CFUNCTYPE(None, PVOID)
HOSTSERVICES_DESTROYTARGET = ctypes.CFUNCTYPE(None, PVOID)
HOSTSERVICES_DISPATCHCOMMAND = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, PCSTR, ctypes.c_bool)
HOSTSERVICES_UNINITIALIZE = ctypes.CFUNCTYPE(None, PVOID)

# --- VTable and Interface Structure Definitions ---
class IUnknownVtbl(ctypes.Structure):
    _fields_ = [
        ("QueryInterface", QI_FUNC_TYPE),
        ("AddRef", ADDREF_FUNC_TYPE),
        ("Release", RELEASE_FUNC_TYPE),
    ]

class IMemoryServiceVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("ReadVirtual", READ_VIRTUAL_FUNC_TYPE),
        # Other IMemoryService methods would go here
    ]

class IDebuggerServicesVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("GetOperatingSystem", GET_OPERATING_SYSTEM_FUNC_TYPE),
        ("GetDebuggeeType", DBG_GET_DEBUGGEE_TYPE_FUNC_TYPE),
        ("GetProcessorType", DBG_GET_PROCESSOR_TYPE_FUNC_TYPE),
        ("AddCommand", DBG_ADD_COMMAND_FUNC_TYPE),
        ("OutputString", DBG_OUTPUT_STRING_FUNC_TYPE),
        ("ReadVirtual", DBG_READ_VIRTUAL_FUNC_TYPE),
        ("WriteVirtual", DBG_WRITE_VIRTUAL_FUNC_TYPE),
        ("GetNumberModules", DBG_GET_NUMBER_MODULES_FUNC_TYPE),
        ("GetModuleByIndex", DBG_GET_MODULE_BY_INDEX_FUNC_TYPE),
        ("GetModuleNames", DBG_GET_MODULE_NAMES_FUNC_TYPE),
        ("GetModuleInfo", DBG_GET_MODULE_INFO_FUNC_TYPE),
        ("GetModuleVersionInformation", DBG_GET_MODULE_VERSION_INFO_FUNC_TYPE),
        ("GetModuleByModuleName", DBG_GET_MODULE_BY_MODNAME_FUNC_TYPE),
        ("GetNumberThreads", DBG_GET_NUMBER_THREADS_FUNC_TYPE),
        ("GetThreadIdsByIndex", DBG_GET_THREAD_IDS_BY_INDEX_FUNC_TYPE),
        ("GetThreadContextBySystemId", DBG_GET_THREAD_CONTEXT_BY_SYSID_FUNC_TYPE),
        ("GetCurrentProcessSystemId", DBG_GET_CURRENT_PROCESS_SYSID_FUNC_TYPE),
        ("GetCurrentThreadSystemId", DBG_GET_CURRENT_THREAD_SYSID_FUNC_TYPE),
        ("SetCurrentThreadSystemId", DBG_SET_CURRENT_THREAD_SYSID_FUNC_TYPE),
        ("GetThreadTeb", DBG_GET_THREAD_TEB_FUNC_TYPE),
        ("VirtualUnwind", DBG_VIRTUAL_UNWIND_FUNC_TYPE),
        ("GetSymbolPath", DBG_GET_SYMBOL_PATH_FUNC_TYPE),
        ("GetSymbolByOffset", DBG_GET_SYMBOL_BY_OFFSET_FUNC_TYPE),
        ("GetOffsetBySymbol", DBG_GET_OFFSET_BY_SYMBOL_FUNC_TYPE),
        ("GetTypeId", DBG_GET_TYPE_ID_FUNC_TYPE),
        ("GetFieldOffset", DBG_GET_FIELD_OFFSET_FUNC_TYPE),
        ("GetOutputWidth", DBG_GET_OUTPUT_WIDTH_FUNC_TYPE),
        ("SupportsDml", DBG_SUPPORTS_DML_FUNC_TYPE),
        ("OutputDmlString", DBG_OUTPUT_DML_STRING_FUNC_TYPE),
        ("AddModuleSymbol", DBG_ADD_MODULE_SYMBOL_FUNC_TYPE),
        ("GetLastEventInformation", DBG_GET_LAST_EVENT_INFO_FUNC_TYPE),
        ("FlushCheck", DBG_FLUSH_CHECK_FUNC_TYPE),
        ("ExecuteHostCommand", DBG_EXECUTE_HOST_COMMAND_FUNC_TYPE),
        ("GetDacSignatureVerificationSettings", DBG_GET_DAC_SIG_VER_SETTINGS_FUNC_TYPE),
    ]

class IHostVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
    ("GetHostType", GET_HOST_TYPE_FUNC_TYPE),
    ("GetService", GET_SERVICE_FUNC_TYPE),
    ("GetCurrentTarget", GET_CURRENT_TARGET_FUNC_TYPE),
    ]

class IMemoryService(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IMemoryServiceVtbl))]

class IDebuggerServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IDebuggerServicesVtbl))]

class IHost(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IHostVtbl))]

# --- IHostServices (from hostservices.h) ---
class IHostServicesVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("GetHost", HOSTSERVICES_GETHOST),
        ("RegisterDebuggerServices", HOSTSERVICES_REGISTERDEBUGGER),
        ("CreateTarget", HOSTSERVICES_CREATETARGET),
        ("UpdateTarget", HOSTSERVICES_UPDATETARGET),
        ("FlushTarget", HOSTSERVICES_FLUSHTARGET),
        ("DestroyTarget", HOSTSERVICES_DESTROYTARGET),
        ("DispatchCommand", HOSTSERVICES_DISPATCHCOMMAND),
        ("Uninitialize", HOSTSERVICES_UNINITIALIZE),
    ]

class IHostServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IHostServicesVtbl))]

# --- ILLDBServices (full COM interface) ---
class ILLDBServicesVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        # ILLDBServices custom
        ("GetCoreClrDirectory", ctypes.CFUNCTYPE(PCSTR, PVOID)),
        ("GetExpression", ctypes.CFUNCTYPE(ULONG64, PVOID, PCSTR)),
    ("VirtualUnwind", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, PVOID)),
        ("SetExceptionCallback", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)),
        ("ClearExceptionCallback", ctypes.CFUNCTYPE(HRESULT, PVOID)),
        # IDebugControl2
        ("GetInterrupt", ctypes.CFUNCTYPE(HRESULT, PVOID)),
        ("OutputVaList", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, PVOID)),
        ("GetDebuggeeType", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))),
        ("GetPageSize", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetProcessorType", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("Execute", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG)),
        ("GetLastEventInformation", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), PVOID, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))),
        ("Disassemble", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        # IDebugControl4
        ("GetContextStackTrace", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG, ULONG, ctypes.POINTER(ULONG))),
        # IDebugDataSpaces
        ("ReadVirtual", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))),
        ("WriteVirtual", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))),
        # IDebugSymbols
        ("GetSymbolOptions", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetNameByOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetNumberModules", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))),
        ("GetModuleByIndex", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))),
        ("GetModuleByModuleName", ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetModuleByOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
    ("GetModuleNames", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))),
        ("GetLineByOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetSourceFileLineOffsets", ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ULONG64), ULONG, ctypes.POINTER(ULONG))),
        ("FindSourceFile", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))),
        # IDebugSystemObjects subset
        ("GetCurrentProcessSystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetCurrentThreadId", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("SetCurrentThreadId", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)),
        ("GetCurrentThreadSystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetThreadIdBySystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG))),
    ("GetThreadContextBySystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, ULONG, PVOID)),
        # IDebugRegister subset
        ("GetValueByName", ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ctypes.c_size_t))),
        ("GetInstructionOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))),
        ("GetStackOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))),
        ("GetFrameOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))),
    ]

class ILLDBServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(ILLDBServicesVtbl))]

class ILLDBServices2Vtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("LoadNativeSymbols", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_bool, PVOID)),
        ("AddModuleSymbol", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, PCSTR)),
    ("GetModuleInfo", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))),
    ("GetModuleVersionInformation", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, PCSTR, PVOID, ULONG, ctypes.POINTER(ULONG))),
        ("SetRuntimeLoadedCallback", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)),
    ]

class ILLDBServices2(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(ILLDBServices2Vtbl))]


# --- Python Implementation of the Services ---

class GdbServices:
    """Implements the SOS services interfaces in Python."""
    def __init__(self):
        self._ref = 0
        # Caches for discovered runtime
        self._coreclr_base = None
        self._coreclr_path = None
        self._coreclr_dir_buf = None
        # Create the vtable for the base IUnknown interface first.
        iunknown_vtbl = IUnknownVtbl(
            QI_FUNC_TYPE(self.query_interface),
            ADDREF_FUNC_TYPE(self.add_ref),
            RELEASE_FUNC_TYPE(self.release)
        )

        # Now, create the derived vtables, passing the base vtable instance
        # as the first argument.
        self._imemory_vtbl = IMemoryServiceVtbl(
            iunknown_vtbl,
            READ_VIRTUAL_FUNC_TYPE(self.read_virtual)
        )
        self._idebugger_vtbl = IDebuggerServicesVtbl(
            iunknown_vtbl,
            GET_OPERATING_SYSTEM_FUNC_TYPE(self.dbg_get_operating_system),
            DBG_GET_DEBUGGEE_TYPE_FUNC_TYPE(self.lldb_get_debuggee_type),
            DBG_GET_PROCESSOR_TYPE_FUNC_TYPE(self.lldb_get_processor_type),
            DBG_ADD_COMMAND_FUNC_TYPE(self.dbg_add_command),
            DBG_OUTPUT_STRING_FUNC_TYPE(self.dbg_output_string),
            DBG_READ_VIRTUAL_FUNC_TYPE(self.lldb_read_virtual),
            DBG_WRITE_VIRTUAL_FUNC_TYPE(self.lldb_write_virtual),
            DBG_GET_NUMBER_MODULES_FUNC_TYPE(self.lldb_get_number_modules),
            DBG_GET_MODULE_BY_INDEX_FUNC_TYPE(self.lldb_get_module_by_index),
            DBG_GET_MODULE_NAMES_FUNC_TYPE(self.dbg_get_module_names),
            DBG_GET_MODULE_INFO_FUNC_TYPE(self.dbg_get_module_info),
            DBG_GET_MODULE_VERSION_INFO_FUNC_TYPE(self.lldb2_get_module_version_information),
            DBG_GET_MODULE_BY_MODNAME_FUNC_TYPE(self.lldb_get_module_by_module_name),
            DBG_GET_NUMBER_THREADS_FUNC_TYPE(self.dbg_get_number_threads),
            DBG_GET_THREAD_IDS_BY_INDEX_FUNC_TYPE(self.dbg_get_thread_ids_by_index),
            DBG_GET_THREAD_CONTEXT_BY_SYSID_FUNC_TYPE(self.lldb_get_thread_context_by_system_id),
            DBG_GET_CURRENT_PROCESS_SYSID_FUNC_TYPE(self.lldb_get_current_process_system_id),
            DBG_GET_CURRENT_THREAD_SYSID_FUNC_TYPE(self.lldb_get_current_thread_system_id),
            DBG_SET_CURRENT_THREAD_SYSID_FUNC_TYPE(self.dbg_set_current_thread_system_id),
            DBG_GET_THREAD_TEB_FUNC_TYPE(self.dbg_get_thread_teb),
            DBG_VIRTUAL_UNWIND_FUNC_TYPE(self.lldb_virtual_unwind),
            DBG_GET_SYMBOL_PATH_FUNC_TYPE(self.dbg_get_symbol_path),
            DBG_GET_SYMBOL_BY_OFFSET_FUNC_TYPE(self.dbg_get_symbol_by_offset),
            DBG_GET_OFFSET_BY_SYMBOL_FUNC_TYPE(self.dbg_get_offset_by_symbol),
            DBG_GET_TYPE_ID_FUNC_TYPE(self.dbg_get_type_id),
            DBG_GET_FIELD_OFFSET_FUNC_TYPE(self.dbg_get_field_offset),
            DBG_GET_OUTPUT_WIDTH_FUNC_TYPE(self.dbg_get_output_width),
            DBG_SUPPORTS_DML_FUNC_TYPE(self.dbg_supports_dml),
            DBG_OUTPUT_DML_STRING_FUNC_TYPE(self.dbg_output_dml_string),
            DBG_ADD_MODULE_SYMBOL_FUNC_TYPE(self.lldb2_add_module_symbol),
            DBG_GET_LAST_EVENT_INFO_FUNC_TYPE(self.lldb_get_last_event_information),
            DBG_FLUSH_CHECK_FUNC_TYPE(self.dbg_flush_check),
            DBG_EXECUTE_HOST_COMMAND_FUNC_TYPE(self.dbg_execute_host_command),
            DBG_GET_DAC_SIG_VER_SETTINGS_FUNC_TYPE(self.dbg_get_dac_signature_ver_settings),
        )
        self._ihost_vtbl = IHostVtbl(
            iunknown_vtbl,
            GET_HOST_TYPE_FUNC_TYPE(self.host_get_host_type),
            GET_SERVICE_FUNC_TYPE(self.host_get_service),
            GET_CURRENT_TARGET_FUNC_TYPE(self.host_get_current_target),
        )
        # IHostServices vtable
        self._ihostservices_vtbl = IHostServicesVtbl(
            iunknown_vtbl,
            HOSTSERVICES_GETHOST(self.hostservices_get_host),
            HOSTSERVICES_REGISTERDEBUGGER(self.hostservices_register_debugger_services),
            HOSTSERVICES_CREATETARGET(self.hostservices_create_target),
            HOSTSERVICES_UPDATETARGET(self.hostservices_update_target),
            HOSTSERVICES_FLUSHTARGET(self.hostservices_flush_target),
            HOSTSERVICES_DESTROYTARGET(self.hostservices_destroy_target),
            HOSTSERVICES_DISPATCHCOMMAND(self.hostservices_dispatch_command),
            HOSTSERVICES_UNINITIALIZE(self.hostservices_uninitialize),
        )
        # ILLDBServices vtable
        self._illldb_vtbl = ILLDBServicesVtbl(
            iunknown_vtbl,
            ctypes.CFUNCTYPE(PCSTR, PVOID)(self.lldb_get_coreclr_directory),
            ctypes.CFUNCTYPE(ULONG64, PVOID, PCSTR)(self.lldb_get_expression),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, PVOID)(self.lldb_virtual_unwind),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)(self.lldb_set_exception_callback),
            ctypes.CFUNCTYPE(HRESULT, PVOID)(self.lldb_clear_exception_callback),
            ctypes.CFUNCTYPE(HRESULT, PVOID)(self.lldb_get_interrupt),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, PVOID)(self.lldb_output_va_list),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))(self.lldb_get_debuggee_type),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_page_size),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_processor_type),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG)(self.lldb_execute),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), PVOID, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_last_event_information),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_disassemble),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_context_stack_trace),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb_read_virtual),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb_write_virtual),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_symbol_options),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_name_by_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))(self.lldb_get_number_modules),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))(self.lldb_get_module_by_index),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_module_by_module_name),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_module_by_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_module_names),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_line_by_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ULONG64), ULONG, ctypes.POINTER(ULONG))(self.lldb_get_source_file_line_offsets),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_find_source_file),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_current_process_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_current_thread_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)(self.lldb_set_current_thread_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_current_thread_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_thread_id_by_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, ULONG, PVOID)(self.lldb_get_thread_context_by_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ctypes.c_size_t))(self.lldb_get_value_by_name),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))(self.lldb_get_instruction_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))(self.lldb_get_stack_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))(self.lldb_get_frame_offset),
        )
        self._illldb2_vtbl = ILLDBServices2Vtbl(
            iunknown_vtbl,
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_bool, PVOID)(self.lldb2_load_native_symbols),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, PCSTR)(self.lldb2_add_module_symbol),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))(self.lldb2_get_module_info),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, PCSTR, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb2_get_module_version_information),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)(self.lldb2_set_runtime_loaded_callback),
        )
        # Create interface pointers
        self.imemory_ptr = IMemoryService(ctypes.pointer(self._imemory_vtbl))
        self.idebugger_ptr = IDebuggerServices(ctypes.pointer(self._idebugger_vtbl))
        self.ihost_ptr = IHost(ctypes.pointer(self._ihost_vtbl))
        self.ihostservices_ptr = IHostServices(ctypes.pointer(self._ihostservices_vtbl))
        self.illldb_ptr = ILLDBServices(ctypes.pointer(self._illldb_vtbl))
        self.illldb2_ptr = ILLDBServices2(ctypes.pointer(self._illldb2_vtbl))
        self._registered_debugger = None

    # --- Trace helper ---
    def _trace(self, msg: str):
        if not TRACE_ENABLED:
            return
        try:
            gdb.write(msg + "\n")
        except Exception:
            pass

    # --- IUnknown Implementation ---
    def query_interface(self, this_ptr, iid_ptr, obj_ptr):
        iid = iid_ptr.contents

        def guid_bytes_le(g: GUID) -> bytes:
            # Read the raw 16 bytes in memory order (little-endian for Data1-3)
            return ctypes.string_at(ctypes.byref(g), ctypes.sizeof(GUID))

        def guid_equal(a: GUID, b: GUID) -> bool:
            return guid_bytes_le(a) == guid_bytes_le(b)

        def fmt_guid(g: GUID) -> str:
            try:
                import uuid
                return str(uuid.UUID(bytes_le=guid_bytes_le(g))).upper()
            except Exception:
                return "<INVALID-GUID>"

        if TRACE_ENABLED:
            try:
                gdb.write(f"QueryInterface called for IID {fmt_guid(iid)}\n")
            except Exception:
                pass

        if guid_equal(iid, IID_IUnknown) or guid_equal(iid, IID_IDebuggerServices):
            obj_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
            if TRACE_ENABLED:
                try:
                    gdb.write("QI -> IDebuggerServices\n")
                except Exception:
                    pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_IMemoryService):
            obj_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
            if TRACE_ENABLED:
                try:
                    gdb.write("QI -> IMemoryService\n")
                except Exception:
                    pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_IHost):
            obj_ptr.contents.value = ctypes.addressof(self.ihost_ptr)
            if TRACE_ENABLED:
                try:
                    gdb.write("QI -> IHost\n")
                except Exception:
                    pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_ILLDBServices):
            obj_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
            if TRACE_ENABLED:
                try:
                    gdb.write("QI -> ILLDBServices (stub)\n")
                except Exception:
                    pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_ILLDBServices2):
            obj_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
            if TRACE_ENABLED:
                try:
                    gdb.write("QI -> ILLDBServices2 (stub)\n")
                except Exception:
                    pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        obj_ptr.contents.value = 0
        if TRACE_ENABLED:
            try:
                gdb.write("QI -> E_NOINTERFACE\n")
            except Exception:
                pass
        return 0x80004002 # E_NOINTERFACE

    def add_ref(self, this_ptr):
        self._ref += 1
        return self._ref

    def release(self, this_ptr):
        self._ref -= 1
        if self._ref == 0:
            # In a real app, might free resources here
            pass
        return self._ref

    # --- IDebuggerServices Implementation ---
    # All methods are implemented as dbg_* or lldb_* above and wired in the vtable

    # --- IMemoryService Implementation ---
    def read_virtual(self, this_ptr, address, buffer, bytes_requested, bytes_read_ptr):
        self._trace("call into read_virtual")
        try:
            # Use the GDB Python API to read memory from the inferior process
            inferior = gdb.selected_inferior()
            mem = inferior.read_memory(address, bytes_requested)
            bytes_read = len(mem)
            ctypes.memmove(buffer, mem.tobytes(), bytes_read)
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = bytes_read
            return 0 # S_OK
        except gdb.MemoryError:
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = 0
            return 0x80070005 # E_FAIL

    # --- IHost Implementation ---
    def host_get_host_type(self, this_ptr):
        self._trace("call into host_get_host_type")
        # Map to IHost::HostType enum (DotnetDump=0, Lldb=1, DbgEng=2, Vs=3)
        # Choose DotnetDump to avoid dbgeng-specific branches.
        return 0

    def host_get_service(self, this_ptr, guid_ptr, out_ptr):
        self._trace("call into host_get_service")
        # Trace the requested GUID and try to provide common services
        if TRACE_ENABLED:
            try:
                if guid_ptr:
                    g = guid_ptr.contents
                    b = ctypes.string_at(ctypes.byref(g), ctypes.sizeof(GUID))
                    import uuid
                    guid_str = str(uuid.UUID(bytes_le=b)).upper()
                    gdb.write(f"call into host_get_service for IID {guid_str}\n")
            except Exception:
                pass

        if out_ptr:
            out_ptr.contents.value = 0

        # Provide common services directly from the host
        def guid_equal(a: GUID, b: GUID) -> bool:
            return ctypes.string_at(ctypes.byref(a), ctypes.sizeof(GUID)) == ctypes.string_at(ctypes.byref(b), ctypes.sizeof(GUID))

        if guid_ptr:
            iid = guid_ptr.contents
            if guid_equal(iid, IID_ILLDBServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
                self.add_ref(this_ptr)
                return 0
            if guid_equal(iid, IID_ILLDBServices2):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
                self.add_ref(this_ptr)
                return 0
            if guid_equal(iid, IID_IHostServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.ihostservices_ptr)
                self.add_ref(this_ptr)
                return 0
            if guid_equal(iid, IID_IDebuggerServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
                self.add_ref(this_ptr)
                return 0
            if guid_equal(iid, IID_IMemoryService):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
                self.add_ref(this_ptr)
                return 0

        return 0x80004002 # E_NOINTERFACE

    def host_get_current_target(self, this_ptr, out_ptr):
        self._trace("call into host_get_current_target")
        # Explicitly indicate not implemented so SOS doesn't rely on this path
        if out_ptr:
            out_ptr.contents.value = 0
        return 0x80004001  # E_NOTIMPL

    # --- ILLDBServices2 stub methods ---
    def lldb2_load_native_symbols(self, this_ptr, runtimeOnly, callback):
        self._trace("call into lldb2_load_native_symbols")
        # For POC, do nothing
        return 0 # S_OK

    def lldb2_add_module_symbol(self, this_ptr, param, symbolFilePath):
        self._trace("call into lldb2_add_module_symbol")
        return 0 # S_OK

    def lldb2_get_module_info(self, this_ptr, index, moduleBase, moduleSize, timestamp, checksum):
        self._trace(f"call into lldb2_get_module_info index={index}")
        # We only support a single module (libcoreclr.so) at index 0
        if index != 0:
            return 0x80004005  # E_FAIL

        # Ensure we have path/base cached
        path, base_addr = self._scan_coreclr()
        if not path or base_addr is None:
            return 0x80004005  # E_FAIL

        # Compute an approximate module size by union of libcoreclr.so mappings
        pid = self._get_pid()
        min_start = None
        max_end = None
        try:
            if pid:
                maps_path = f"/proc/{pid}/maps"
                with open(maps_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'libcoreclr.so' not in line:
                            continue
                        parts = line.strip().split()
                        if len(parts) < 6:
                            continue
                        # Recompose path and normalize deleted marker
                        p = ' '.join(parts[5:])
                        if p.endswith(' (deleted)'):
                            p = p[:-10]
                        if not p.startswith('/'):
                            continue
                        if p != path:
                            continue
                        try:
                            start_str, end_str = parts[0].split('-')
                            start = int(start_str, 16)
                            end = int(end_str, 16)
                        except Exception:
                            continue
                        if min_start is None or start < min_start:
                            min_start = start
                        if max_end is None or end > max_end:
                            max_end = end
        except Exception as ex:
            self._trace(f"GetModuleInfo maps scan error: {ex}")

        size_val = 0
        if min_start is not None and max_end is not None and max_end > min_start:
            size_val = max_end - min_start

        if moduleBase:
            moduleBase.contents.value = ctypes.c_uint64(base_addr).value
        if moduleSize:
            moduleSize.contents.value = ctypes.c_uint64(size_val).value
        if timestamp:
            timestamp.contents.value = 0
        if checksum:
            checksum.contents.value = 0
        self._trace(f"  -> base=0x{base_addr:x} size=0x{size_val:x}")
        return 0  # S_OK

    def lldb2_get_module_version_information(self, this_ptr, index, base, item, buffer, bufferSize, versionInfoSize):
        self._trace("call into lldb2_get_module_version_information")
        return 0x80004001 # E_NOTIMPL

    def lldb2_set_runtime_loaded_callback(self, this_ptr, callback):
        self._trace("call into lldb2_set_runtime_loaded_callback")
        return 0 # S_OK

    # --- ILLDBServices stub methods ---
    # --- Helpers ---
    def _get_pid(self):
        try:
            inf = gdb.selected_inferior()
            pid = getattr(inf, 'pid', None)
            if pid and pid > 0:
                return pid
        except Exception:
            pass
        return None

    def _scan_coreclr(self):
        pid = self._get_pid()
        if not pid:
            return None, None
        maps_path = f"/proc/{pid}/maps"
        found_path = None
        base = None
        try:
            with open(maps_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'libcoreclr.so' not in line:
                        continue
                    parts = line.rstrip('\n').split()
                    if len(parts) < 6:
                        continue
                    addr_range = parts[0]
                    # Reconstruct path from 6th token onward to handle " (deleted)"
                    path_field = ' '.join(parts[5:])
                    # Normalize: strip trailing " (deleted)" marker if present
                    if path_field.endswith(' (deleted)'):
                        path_field = path_field[:-10]
                    path = path_field if path_field.startswith('/') else None
                    if not path:
                        continue
                    try:
                        start_str = addr_range.split('-')[0]
                        start = int(start_str, 16)
                    except Exception:
                        continue
                    if found_path is None:
                        found_path = path
                        base = start
                    else:
                        # choose the lowest start for the same file
                        if start < base:
                            base = start
            if found_path:
                self._coreclr_path = found_path
                self._coreclr_base = base
                # Keep directory buffer alive
                directory = os.path.dirname(found_path)
                if directory:
                    path_bytes = directory.encode('utf-8')
                    self._coreclr_dir_buf = ctypes.create_string_buffer(path_bytes + b"\x00")
                self._trace(f"_scan_coreclr found path={self._coreclr_path} base=0x{self._coreclr_base:x}")
                return self._coreclr_path, self._coreclr_base
        except Exception as ex:
            self._trace(f"_scan_coreclr error: {ex}")
        # not found
        self._coreclr_path = None
        self._coreclr_base = None
        self._coreclr_dir_buf = None
        return None, None
    # --- IHostServices stub methods ---
    def hostservices_get_host(self, this_ptr, ppHost):
        self._trace("call into hostservices_get_host (disabled)")
        # Don't provide an IHost so SOS uses internal target discovery
        if ppHost:
            ppHost.contents.value = 0
        return 0x80004002  # E_NOINTERFACE

    # --- IDebuggerServices minimal implementations ---
    def dbg_get_operating_system(self, this_ptr, os_ptr):
        # Linux
        if os_ptr:
            os_ptr.contents.value = 2
        return 0

    def dbg_add_command(self, this_ptr, command, help_text, aliases, numberOfAliases):
        return 0

    def dbg_output_string(self, this_ptr, mask, message):
        try:
            gdb.write(message.decode() if isinstance(message, (bytes, bytearray)) else str(message))
        except Exception:
            pass

    def dbg_get_module_info(self, this_ptr, index, moduleBase, moduleSize, timestamp, checksum):
        # For coreclr at index 0
        _, base = self._scan_coreclr()
        if index != 0 or base is None:
            return 0x80004005
        # reuse size logic from lldb2_get_module_info
        size = ctypes.c_uint64(0)
        dummy_ts = ctypes.c_uint32(0)
        dummy_cs = ctypes.c_uint32(0)
        self.lldb2_get_module_info(None, 0, moduleBase, ctypes.byref(size), ctypes.byref(dummy_ts), ctypes.byref(dummy_cs))
        if moduleSize:
            moduleSize.contents.value = size.value
        if timestamp:
            timestamp.contents.value = 0
        if checksum:
            checksum.contents.value = 0
        return 0

    def dbg_get_module_names(self, this_ptr, index, base, imageNameBuffer, imageNameBufferSize, imageNameSize, moduleNameBuffer, moduleNameBufferSize, moduleNameSize, loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize):
        path, _ = self._scan_coreclr()
        if index != 0 or not path:
            return 0x80004005
        img = path.encode('utf-8')
        name = os.path.basename(path).encode('utf-8')
        def fill(buf_voidp, bufSize, sizePtr, data_bytes):
            try:
                if sizePtr:
                    sizePtr.contents.value = len(data_bytes) + 1
                if not buf_voidp or not bufSize or bufSize <= 0:
                    return
                # Compute destination address integer
                addr = buf_voidp if isinstance(buf_voidp, int) else ctypes.cast(buf_voidp, ctypes.c_void_p).value
                if not addr:
                    return
                n = min(len(data_bytes), max(0, bufSize - 1))
                if n > 0:
                    ctypes.memmove(addr, data_bytes, n)
                # Null-terminate at offset n
                ctypes.memmove(addr + n, b"\x00", 1)
            except Exception as ex:
                # Never raise from a ctypes callback
                try:
                    self._trace(f"lldb_get_module_names.fill error: {ex}")
                except Exception:
                    pass
        fill(imageNameBuffer, imageNameBufferSize, imageNameSize, img)
        fill(moduleNameBuffer, moduleNameBufferSize, moduleNameSize, name)
        fill(loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize, img)
        return 0

    def dbg_get_number_threads(self, this_ptr, number_ptr):
        if number_ptr:
            number_ptr.contents.value = 0
        return 0

    def dbg_get_thread_ids_by_index(self, this_ptr, start, count, ids, sysIds):
        return 0

    def dbg_set_current_thread_system_id(self, this_ptr, sysId):
        return 0

    def dbg_get_thread_teb(self, this_ptr, sysId, pteb):
        return 0x80004001

    def dbg_get_symbol_path(self, this_ptr, buffer, bufferSize, pathSize):
        if pathSize:
            pathSize.contents.value = 1
        if buffer and bufferSize:
            buffer[0] = 0
        return 0

    def dbg_get_symbol_by_offset(self, this_ptr, moduleIndex, offset, nameBuffer, nameBufferSize, nameSize, displacement):
        return 0x80004001

    def dbg_get_offset_by_symbol(self, this_ptr, moduleIndex, name, offset):
        return 0x80004001

    def dbg_get_type_id(self, this_ptr, moduleIndex, typeName, typeId):
        return 0x80004001

    def dbg_get_field_offset(self, this_ptr, moduleIndex, typeName, typeId, fieldName, offset):
        return 0x80004001

    def dbg_get_output_width(self, this_ptr):
        return 80

    def dbg_supports_dml(self, this_ptr, supported):
        if supported:
            supported.contents.value = 0
        return 0

    def dbg_output_dml_string(self, this_ptr, mask, message):
        self.dbg_output_string(this_ptr, mask, message)

    def dbg_flush_check(self, this_ptr):
        return None

    def dbg_execute_host_command(self, this_ptr, commandLine, callback):
        return 0x80004001

    def dbg_get_dac_signature_ver_settings(self, this_ptr, enabled_ptr):
        # Disable DAC signature verification so SOS can load DAC/DBI from runtime dir
        if enabled_ptr:
            enabled_ptr.contents.value = 0
        return 0

    def hostservices_register_debugger_services(self, this_ptr, iunk):
        self._trace("call into hostservices_register_debugger_services")
        self._registered_debugger = iunk
        return 0

    def hostservices_create_target(self, this_ptr):
        self._trace("call into hostservices_create_target")
        return 0

    def hostservices_update_target(self, this_ptr, processId):
        self._trace(f"call into hostservices_update_target pid={processId}")
        return 0

    def hostservices_flush_target(self, this_ptr):
        self._trace("call into hostservices_flush_target")
        # void

    def hostservices_destroy_target(self, this_ptr):
        self._trace("call into hostservices_destroy_target")
        # void

    def hostservices_dispatch_command(self, this_ptr, commandName, arguments, displayCommandNotFound):
        try:
            cn = commandName.decode() if commandName else None
            args = arguments.decode() if arguments else None
            self._trace(f"call into hostservices_dispatch_command cmd={cn} args={args} displayCNF={bool(displayCommandNotFound)}")
        except Exception:
            self._trace("call into hostservices_dispatch_command")
        # For now, not implemented to route to managed extensions
        return 0x80004001

    def hostservices_uninitialize(self, this_ptr):
        self._trace("call into hostservices_uninitialize")
        # void
    def lldb_get_coreclr_directory(self, this_ptr):
        self._trace("call into lldb_get_coreclr_directory")
        try:
            path, base = self._scan_coreclr()
            if path and self._coreclr_dir_buf:
                self._trace(f"coreclr directory: {os.path.dirname(path)} base=0x{base:x}")
                return ctypes.cast(self._coreclr_dir_buf, ctypes.c_char_p)
        except Exception as ex:
            self._trace(f"lldb_get_coreclr_directory error: {ex}")
        self._trace("coreclr directory: NOT FOUND")
        return None
    def lldb_get_expression(self, this_ptr, exp):
        self._trace("call into lldb_get_expression")
        try:
            expr = exp.decode() if isinstance(exp, (bytes, bytearray)) else exp
            val = gdb.parse_and_eval(expr)
            # Try to coerce to integer address/value
            try:
                return int(val)
            except Exception:
                # Fallback: cast to unsigned long long if possible
                try:
                    return int(val.cast(gdb.lookup_type('unsigned long long')))
                except Exception:
                    return 0
        except Exception:
            return 0
    def lldb_virtual_unwind(self, this_ptr, threadID, contextSize, context):
        self._trace("call into lldb_virtual_unwind")
        return 0x80004001
    def lldb_set_exception_callback(self, this_ptr, cb):
        self._trace("call into lldb_set_exception_callback")
        return 0
    def lldb_clear_exception_callback(self, this_ptr):
        self._trace("call into lldb_clear_exception_callback")
        return 0
    def lldb_get_interrupt(self, this_ptr):
        self._trace("call into lldb_get_interrupt")
        # dbgeng semantics: S_OK if interrupted, S_FALSE if not.
        return 1  # S_FALSE: no user interrupt pending
    def lldb_output_va_list(self, this_ptr, mask, fmt, va_list_ptr):
        self._trace("call into lldb_output_va_list")
        try:
            # Use libc.vsnprintf to format the message using the provided va_list
            # Allocate a buffer and grow if needed
            libc = getattr(self, "_libc_handle", None)
            if libc is None:
                try:
                    libc = ctypes.CDLL("libc.so.6")
                except Exception:
                    libc = ctypes.CDLL(None)
                self._libc_handle = libc

            vsnprintf = getattr(self, "_vsnprintf_func", None)
            if vsnprintf is None:
                vsnprintf = libc.vsnprintf
                vsnprintf.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_void_p]
                vsnprintf.restype = ctypes.c_int
                self._vsnprintf_func = vsnprintf

            # Initial buffer
            size = 1024
            while True:
                buf = ctypes.create_string_buffer(size)
                # Important: we must not reuse va_list across calls; but within this loop,
                # we only call once unless it needs to grow. On many ABIs, after one use
                # the va_list is advanced. To be safe, bail out if needs grow.
                written = vsnprintf(buf, size, fmt, va_list_ptr)
                if written < 0:
                    # Formatting error; stop
                    break
                if written >= size:
                    # Buffer too small; try once with the exact size. Avoid looping with same va_list.
                    size = written + 1
                    # One retry only to avoid undefined va_list reuse issues
                    buf = ctypes.create_string_buffer(size)
                    vsnprintf(buf, size, fmt, va_list_ptr)
                # Write the result to GDB console
                try:
                    gdb.write(buf.value.decode(errors='replace'))
                except Exception:
                    # Fallback to stdout
                    sys.stdout.write(buf.value.decode(errors='replace'))
                break
        except Exception:
            pass
        return 0
    def lldb_get_debuggee_type(self, this_ptr, debugClass, qualifier):
        self._trace("call into lldb_get_debuggee_type")
        if debugClass:
            debugClass.contents.value = DEBUG_CLASS_USER_WINDOWS
        if qualifier:
            qualifier.contents.value = DEBUG_DUMP_FULL
        return 0
    def lldb_get_page_size(self, this_ptr, size_ptr):
        self._trace("call into lldb_get_page_size")
        if size_ptr:
            size_ptr.contents.value = 4096
        return 0
    def lldb_get_processor_type(self, this_ptr, type_ptr):
        self._trace("call into lldb_get_processor_type")
        if type_ptr:
            type_ptr.contents.value = IMAGE_FILE_MACHINE_AMD64
        return 0
    def lldb_execute(self, this_ptr, outctl, command, flags):
        self._trace("call into lldb_execute")
        try:
            cmd = command.decode() if command else ""
            if cmd and TRACE_ENABLED:
                # Print the command for visibility when tracing
                gdb.write(f"[ILLDBServices.Execute] {cmd}\n")
        except Exception:
            pass
        return 0
    def lldb_get_last_event_information(self, this_ptr, t, pid, tid, extra, extraSize, extraUsed, desc, descSize, descUsed):
        self._trace("call into lldb_get_last_event_information")
        if t: t.contents.value = 0
        if pid: pid.contents.value = 0
        if tid: tid.contents.value = 0
        if extraUsed: extraUsed.contents.value = 0
        if descUsed: descUsed.contents.value = 0
        return 0
    def lldb_disassemble(self, this_ptr, offset, flags, buffer, bufferSize, disSize, endOffset):
        self._trace("call into lldb_disassemble")
        return 0x80004001
    def lldb_get_context_stack_trace(self, this_ptr, startContext, startContextSize, frames, framesSize, frameContexts, frameContextsSize, frameContextsEntrySize, framesFilled):
        self._trace("call into lldb_get_context_stack_trace")
        return 0x80004001
    def lldb_read_virtual(self, this_ptr, address, buffer, bufferSize, bytesRead):
        self._trace("call into lldb_read_virtual")
        return self.read_virtual(this_ptr, address, buffer, bufferSize, bytesRead)
    def lldb_write_virtual(self, this_ptr, address, buffer, bufferSize, bytesWritten):
        self._trace("call into lldb_write_virtual")
        return 0x80004001
    def lldb_get_symbol_options(self, this_ptr, options):
        self._trace("call into lldb_get_symbol_options")
        return 0x80004001
    def lldb_get_name_by_offset(self, this_ptr, offset, nameBuffer, nameBufferSize, nameSize, displacement):
        self._trace("call into lldb_get_name_by_offset")
        return 0x80004001
    def lldb_get_number_modules(self, this_ptr, loaded, unloaded):
        self._trace("call into lldb_get_number_modules")
        path, _ = self._scan_coreclr()
        # Report 1 module if we found coreclr; else 0
        if loaded:
            loaded.contents.value = 1 if path else 0
        if unloaded:
            unloaded.contents.value = 0
        self._trace(f"  -> loaded={loaded.contents.value if loaded else 'n/a'} unloaded={unloaded.contents.value if unloaded else 'n/a'} path={path}")
        return 0  # S_OK
    def lldb_get_module_by_index(self, this_ptr, index, base):
        self._trace(f"call into lldb_get_module_by_index index={index}")
        _, coreclr_base = self._scan_coreclr()
        if index == 0 and coreclr_base is not None:
            if base:
                base.contents.value = ctypes.c_uint64(coreclr_base).value
            self._trace(f"  -> base=0x{coreclr_base:x}")
            return 0  # S_OK
        return 0x80004005  # E_FAIL
    def lldb_get_module_by_module_name(self, this_ptr, name, startIndex, index, base):
        try:
            q = name.decode() if name else ""
        except Exception:
            q = ""
        self._trace(f"call into lldb_get_module_by_module_name name='{q}' startIndex={startIndex}")
        path, coreclr_base = self._scan_coreclr()
        if coreclr_base is None:
            return 0x80004005  # E_FAIL
        # match by basename contains query (case-insensitive)
        base_name = os.path.basename(path)
        if startIndex > 0:
            return 0x80004005  # only a single module supported
        if not q or q.lower() in base_name.lower():
            if index:
                index.contents.value = 0
            if base:
                base.contents.value = ctypes.c_uint64(coreclr_base).value
            self._trace(f"  -> index=0 base=0x{coreclr_base:x}")
            return 0  # S_OK
        return 0x80004005  # E_FAIL
    def lldb_get_module_by_offset(self, this_ptr, offset, startIndex, index, base):
        self._trace("call into lldb_get_module_by_offset")
        return 0x80004001
    def lldb_get_module_names(self, this_ptr, index, base, imageNameBuffer, imageNameBufferSize, imageNameSize, moduleNameBuffer, moduleNameBufferSize, moduleNameSize, loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize):
        self._trace(f"call into lldb_get_module_names index={index} base={base}")
        path, coreclr_base = self._scan_coreclr()
        if not path:
            return 0x80004005  # E_FAIL
        # Support index 0 or DEBUG_ANY_ID with base match
        if index != 0:
            if index != DEBUG_ANY_ID:
                return 0x80004005
            # When index is DEBUG_ANY_ID, base must match coreclr
            try:
                if base != ctypes.c_uint64(coreclr_base).value:
                    return 0x80004005
            except Exception:
                return 0x80004005
        img = path.encode('utf-8')
        name = os.path.basename(path).encode('utf-8')

        def fill(buf_voidp, bufSize, sizePtr, data_bytes):
            try:
                if sizePtr:
                    sizePtr.contents.value = len(data_bytes) + 1
                if not buf_voidp or not bufSize or bufSize <= 0:
                    return
                # Cast void* to char*
                char_p = ctypes.cast(buf_voidp, ctypes.POINTER(ctypes.c_char))
                n = min(len(data_bytes), max(0, bufSize - 1))
                if n > 0:
                    ctypes.memmove(char_p, data_bytes, n)
                # Null-terminate safely
                try:
                    char_p[n] = b"\x00"
                except Exception:
                    # Fallback: use memmove to write a zero byte
                    zero = (ctypes.c_char * 1)()
                    ctypes.memmove(ctypes.cast(ctypes.addressof(char_p.contents) + n, ctypes.c_void_p), zero, 1)
            except Exception as ex:
                self._trace(f"lldb_get_module_names.fill error: {ex}")

        fill(imageNameBuffer, imageNameBufferSize, imageNameSize, img)
        fill(moduleNameBuffer, moduleNameBufferSize, moduleNameSize, name)
        fill(loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize, img)
        return 0
    def lldb_get_line_by_offset(self, this_ptr, offset, line, fileBuffer, fileBufferSize, fileSize, displacement):
        self._trace("call into lldb_get_line_by_offset")
        return 0x80004001
    def lldb_get_source_file_line_offsets(self, this_ptr, file, buffer, bufferLines, fileLines):
        self._trace("call into lldb_get_source_file_line_offsets")
        return 0x80004001
    def lldb_find_source_file(self, this_ptr, startElement, file, flags, foundElement, buffer, bufferSize, foundSize):
        self._trace("call into lldb_find_source_file")
        return 0x80004001
    def lldb_get_current_process_system_id(self, this_ptr, id_ptr):
        self._trace("call into lldb_get_current_process_system_id")
        if id_ptr:
            pid = self._get_pid() or 0
            id_ptr.contents.value = pid
        return 0  # S_OK
    def lldb_get_current_thread_id(self, this_ptr, id_ptr):
        self._trace("call into lldb_get_current_thread_id")
        if id_ptr: id_ptr.contents.value = 0
        return 0
    def lldb_set_current_thread_id(self, this_ptr, id_value):
        self._trace("call into lldb_set_current_thread_id")
        return 0
    def lldb_get_current_thread_system_id(self, this_ptr, sysId):
        self._trace("call into lldb_get_current_thread_system_id")
        if sysId: sysId.contents.value = 0
        return 0
    def lldb_get_thread_id_by_system_id(self, this_ptr, sysId, id_ptr):
        self._trace("call into lldb_get_thread_id_by_system_id")
        return 0x80004001
    def lldb_get_thread_context_by_system_id(self, this_ptr, sysId, contextFlags, contextSize, context):
        self._trace("call into lldb_get_thread_context_by_system_id")
        return 0x80004001
    def lldb_get_value_by_name(self, this_ptr, name, value_ptr):
        self._trace("call into lldb_get_value_by_name")
        return 0x80004001
    def lldb_get_instruction_offset(self, this_ptr, offset_ptr):
        self._trace("call into lldb_get_instruction_offset")
        return 0x80004001
    def lldb_get_stack_offset(self, this_ptr, offset_ptr):
        self._trace("call into lldb_get_stack_offset")
        return 0x80004001
    def lldb_get_frame_offset(self, this_ptr, offset_ptr):
        self._trace("call into lldb_get_frame_offset")
        return 0x80004001

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
                gdb.write("[sos.py] Loading libsos.so...\n")
            SOSCommand.sos_handle = ctypes.CDLL(SOS_LIB_PATH)
            if TRACE_ENABLED:
                gdb.write("[sos.py] Creating GdbServices...\n")
            SOSCommand.gdb_services = GdbServices()

            # Initialize the SOS library
            if TRACE_ENABLED:
                gdb.write("[sos.py] Resolving SOSInitializeByHost...\n")
            init_func = SOSCommand.sos_handle.SOSInitializeByHost
            if TRACE_ENABLED:
                gdb.write("[sos.py] Calling SOSInitializeByHost(NULL, IDebuggerServices) ...\n")
            
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
                }
                candidates = []
                # Manual mapping first
                if cmd in manual:
                    candidates.append(manual[cmd])
                # TitleCase (clrstack -> ClrStack)
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
                gdb.write("[sos.py] Dispatching SOS command with ILLDBServices client\n")
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
# ClrStackCommand = SOSCommand("clrstack")

# --- Trace toggle command ---
class SOSTraceCommand(gdb.Command):
    """Toggle sos.py tracing. Usage: sostrace [on|off|status]"""
    def __init__(self):
        super(SOSTraceCommand, self).__init__("sostrace", gdb.COMMAND_NONE)

    def invoke(self, arg, from_tty):
        global TRACE_ENABLED
        a = (arg or "").strip().lower()
        if a in ("on", "1", "true"):
            TRACE_ENABLED = True
        elif a in ("off", "0", "false"):
            TRACE_ENABLED = False
        elif a in ("", "status"):
            pass
        else:
            gdb.write("Usage: sostrace [on|off|status]\n")
            return
        gdb.write(f"sostrace: {'on' if TRACE_ENABLED else 'off'}\n")

SOSTraceCommand()