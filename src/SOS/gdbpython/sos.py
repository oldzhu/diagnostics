import gdb
import ctypes
import os
import sys

# --- Configuration ---
# This needs to point to the location of your compiled libsos.so
# Adjust this path based on your build output directory.
SOS_LIB_PATH = "/workspaces/diagnostics/artifacts/bin/linux.x64.Debug/libsos.so"

# --- Ctypes Definitions for SOS Interfaces ---
# These definitions must match the C++ headers (debuggerservices.h, pal.h)

# Basic types
HRESULT = ctypes.c_long
ULONG = ctypes.c_ulong
ULONG64 = ctypes.c_ulonglong
PVOID = ctypes.c_void_p
CHAR = ctypes.c_char
PCSTR = ctypes.c_char_p

# GUID structure for QueryInterface
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", (ctypes.c_ubyte * 8)),
    ]

# IIDs from debuggerservices.h
IID_IUnknown = GUID(0x00000000, 0x0000, 0x0000, (0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
IID_IMemoryService = GUID(0x84a8922E, 0x3C6C, 0x4499, (0x9B, 0x4A, 0x3A, 0x62, 0x24, 0x43, 0x5A, 0x79))
IID_IDebuggerServices = GUID(0x2E6C515A, 0x9814, 0x48A5, (0x92, 0x90, 0xF6, 0xDE, 0x4C, 0x24, 0x46, 0x28))

# Function pointer types for the vtables
QI_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(GUID), ctypes.POINTER(PVOID))
ADDREF_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
RELEASE_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
READ_VIRTUAL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))
GET_MEM_SERVICE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(PVOID))

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

class IMemoryService(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IMemoryServiceVtbl))]

class IDebuggerServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IDebuggerServicesVtbl))]


# --- Python Implementation of the Services ---

class GdbServices:
    """Implements the SOS services interfaces in Python."""
    def __init__(self):
        self._ref = 0
        # Create vtables for the COM interfaces.
        # For "inherited" structures, you must pass the arguments for the base
        # fields followed by the derived fields, all in one call.
        self._imemory_vtbl = IMemoryServiceVtbl(
            # IUnknown fields
            QI_FUNC_TYPE(self.query_interface),
            ADDREF_FUNC_TYPE(self.add_ref),
            RELEASE_FUNC_TYPE(self.release),
            # IMemoryService fields
            READ_VIRTUAL_FUNC_TYPE(self.read_virtual)
        )
        self._idebugger_vtbl = IDebuggerServicesVtbl(
            # IUnknown fields
            QI_FUNC_TYPE(self.query_interface),
            ADDREF_FUNC_TYPE(self.add_ref),
            RELEASE_FUNC_TYPE(self.release),
            # IDebuggerServices fields
            GET_MEM_SERVICE_FUNC_TYPE(self.get_memory_service)
        )
        # Create interface pointers
        self.imemory_ptr = IMemoryService(ctypes.pointer(self._imemory_vtbl))
        self.idebugger_ptr = IDebuggerServices(ctypes.pointer(self._idebugger_vtbl))

    # --- IUnknown Implementation ---
    def query_interface(self, this_ptr, iid_ptr, obj_ptr):
        iid = iid_ptr.contents
        if iid == IID_IUnknown or iid == IID_IDebuggerServices:
            obj_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
            self.add_ref(this_ptr)
            return 0 # S_OK
        if iid == IID_IMemoryService:
            obj_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
            self.add_ref(this_ptr)
            return 0 # S_OK
        obj_ptr.contents.value = 0
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
        # Return a pointer to our IMemoryService implementation
        return self.query_interface(this_ptr, ctypes.pointer(IID_IMemoryService), mem_service_ptr)

    # --- IMemoryService Implementation ---
    def read_virtual(self, this_ptr, address, buffer, bytes_requested, bytes_read_ptr):
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
            SOSCommand.sos_handle = ctypes.CDLL(SOS_LIB_PATH)
            SOSCommand.gdb_services = GdbServices()

            # Initialize the SOS library
            init_func = SOSCommand.sos_handle.InitializeForDebuggerServices
            init_func.argtypes = [PVOID]
            init_func.restype = HRESULT
            
            hr = init_func(ctypes.byref(SOSCommand.gdb_services.idebugger_ptr))
            if hr != 0:
                gdb.write(f"InitializeForDebuggerServices failed with HRESULT {hr}.\n")
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
            # Get the address of the function from the command name
            sos_func = getattr(SOSCommand.sos_handle, self.name)
            sos_func.argtypes = [PVOID, PCSTR]
            sos_func.restype = HRESULT

            # Execute the SOS command
            hr = sos_func(ctypes.byref(SOSCommand.gdb_services.idebugger_ptr), arg.encode('utf-8'))
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