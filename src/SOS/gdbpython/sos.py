import gdb
import ctypes
import os
import sys
import re

# --- Configuration ---
# This needs to point to the location of your compiled libsos.so
# Adjust this path based on your build output directory.
SOS_LIB_PATH = "/workspaces/diagnostics/artifacts/bin/linux.x64.Debug/libsos.so"

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
IID_IDebuggerServices = GUID(0x2E6C515A, 0x9814, 0x48A5, (0x92, 0x90, 0xF6, 0xDE, 0x4C, 0x24, 0x46, 0x28))
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

# Function pointer types for the vtables
QI_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(GUID), ctypes.POINTER(PVOID))
ADDREF_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
RELEASE_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
READ_VIRTUAL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))
GET_MEM_SERVICE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(PVOID))
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
        ("GetMemoryService", GET_MEM_SERVICE_FUNC_TYPE),
        # Other IDebuggerServices methods would go here
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
        ("GetModuleNames", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))),
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
            GET_MEM_SERVICE_FUNC_TYPE(self.get_memory_service)
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
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_module_names),
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

        try:
            gdb.write(f"QueryInterface called for IID {fmt_guid(iid)}\n")
        except Exception:
            pass

        if guid_equal(iid, IID_IUnknown) or guid_equal(iid, IID_IDebuggerServices):
            obj_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
            try:
                gdb.write("QI -> IDebuggerServices\n")
            except Exception:
                pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_IMemoryService):
            obj_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
            try:
                gdb.write("QI -> IMemoryService\n")
            except Exception:
                pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_IHost):
            obj_ptr.contents.value = ctypes.addressof(self.ihost_ptr)
            try:
                gdb.write("QI -> IHost\n")
            except Exception:
                pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_ILLDBServices):
            obj_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
            try:
                gdb.write("QI -> ILLDBServices (stub)\n")
            except Exception:
                pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        if guid_equal(iid, IID_ILLDBServices2):
            obj_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
            try:
                gdb.write("QI -> ILLDBServices2 (stub)\n")
            except Exception:
                pass
            self.add_ref(this_ptr)
            return 0 # S_OK
        obj_ptr.contents.value = 0
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
    def get_memory_service(self, this_ptr, mem_service_ptr):
        self._trace("call into get_memory_service")
        # Return a pointer to our IMemoryService implementation
        return self.query_interface(this_ptr, ctypes.pointer(IID_IMemoryService), mem_service_ptr)

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
        # Return success with no target for now
        if out_ptr:
            out_ptr.contents.value = 0
        return 0

    # --- ILLDBServices2 stub methods ---
    def lldb2_load_native_symbols(self, this_ptr, runtimeOnly, callback):
        self._trace("call into lldb2_load_native_symbols")
        # For POC, do nothing
        return 0 # S_OK

    def lldb2_add_module_symbol(self, this_ptr, param, symbolFilePath):
        self._trace("call into lldb2_add_module_symbol")
        return 0 # S_OK

    def lldb2_get_module_info(self, this_ptr, index, moduleBase, moduleSize, timestamp, checksum):
        self._trace("call into lldb2_get_module_info")
        return 0x80004001 # E_NOTIMPL

    def lldb2_get_module_version_information(self, this_ptr, index, base, item, buffer, bufferSize, versionInfoSize):
        self._trace("call into lldb2_get_module_version_information")
        return 0x80004001 # E_NOTIMPL

    def lldb2_set_runtime_loaded_callback(self, this_ptr, callback):
        self._trace("call into lldb2_set_runtime_loaded_callback")
        return 0 # S_OK

    # --- ILLDBServices stub methods ---
    # --- IHostServices stub methods ---
    def hostservices_get_host(self, this_ptr, ppHost):
        self._trace("call into hostservices_get_host")
        if ppHost:
            ppHost.contents.value = ctypes.addressof(self.ihost_ptr)
        self.add_ref(this_ptr)
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
        return 0
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
            if cmd:
                # Print the command for visibility; we don't execute it yet.
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
        if loaded: loaded.contents.value = 0
        if unloaded: unloaded.contents.value = 0
        return 0
    def lldb_get_module_by_index(self, this_ptr, index, base):
        self._trace("call into lldb_get_module_by_index")
        return 0x80004001
    def lldb_get_module_by_module_name(self, this_ptr, name, startIndex, index, base):
        self._trace("call into lldb_get_module_by_module_name")
        return 0x80004001
    def lldb_get_module_by_offset(self, this_ptr, offset, startIndex, index, base):
        self._trace("call into lldb_get_module_by_offset")
        return 0x80004001
    def lldb_get_module_names(self, this_ptr, index, base, imageNameBuffer, imageNameBufferSize, imageNameSize, moduleNameBuffer, moduleNameBufferSize, moduleNameSize, loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize):
        self._trace("call into lldb_get_module_names")
        return 0x80004001
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
        if id_ptr: id_ptr.contents.value = 0
        return 0
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
            gdb.write("before CDLL\n")
            SOSCommand.sos_handle = ctypes.CDLL(SOS_LIB_PATH)
            gdb.write("before set GdbServices\n")
            SOSCommand.gdb_services = GdbServices()

            # Initialize the SOS library
            gdb.write("before set init_func\n")
            init_func = SOSCommand.sos_handle.SOSInitializeByHost
            gdb.write(f"after set {init_func}\n")
            
            # Correctly define the function signature with two PVOID input parameters
            # SOSInitializeByHost(IUnknown* punk, IDebuggerServices* debuggerServices)
            init_func.argtypes = [PVOID, PVOID]
            init_func.restype = HRESULT
            
            # Pass our GdbServices object: first as IHost (punk), second as IDebuggerServices
            hr = init_func(ctypes.byref(SOSCommand.gdb_services.ihost_ptr), ctypes.byref(SOSCommand.gdb_services.idebugger_ptr))
            
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
            gdb.write("dispatching SOS command with ILLDBServices client\n")
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