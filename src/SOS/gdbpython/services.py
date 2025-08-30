import os
import sys
import ctypes
import gdb

# Allow importing when sourced directly (sos.py adjusts sys.path similarly)
from abi import *
from tracing import TRACE_ENABLED, trace


class GdbServices:
    """Implements the SOS services interfaces in Python."""
    def __init__(self):
        self._ref = 0
        self._coreclr_base = None
        self._coreclr_path = None
        self._coreclr_dir_buf = None

        iunknown_vtbl = IUnknownVtbl(QI_FUNC_TYPE(self.query_interface), ADDREF_FUNC_TYPE(self.add_ref), RELEASE_FUNC_TYPE(self.release))

        self._imemory_vtbl = IMemoryServiceVtbl(iunknown_vtbl, READ_VIRTUAL_FUNC_TYPE(self.read_virtual))
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
        self._ihost_vtbl = IHostVtbl(iunknown_vtbl, GET_HOST_TYPE_FUNC_TYPE(self.host_get_host_type), GET_SERVICE_FUNC_TYPE(self.host_get_service), GET_CURRENT_TARGET_FUNC_TYPE(self.host_get_current_target))
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
        self.imemory_ptr = IMemoryService(ctypes.pointer(self._imemory_vtbl))
        self.idebugger_ptr = IDebuggerServices(ctypes.pointer(self._idebugger_vtbl))
        self.ihost_ptr = IHost(ctypes.pointer(self._ihost_vtbl))
        self.ihostservices_ptr = IHostServices(ctypes.pointer(self._ihostservices_vtbl))
        self.illldb_ptr = ILLDBServices(ctypes.pointer(self._illldb_vtbl))
        self.illldb2_ptr = ILLDBServices2(ctypes.pointer(self._illldb2_vtbl))
        self._registered_debugger = None

    # --- IUnknown ---
    def _guid_bytes_le(self, g: GUID) -> bytes:
        return ctypes.string_at(ctypes.byref(g), ctypes.sizeof(GUID))

    def _guid_equal(self, a: GUID, b: GUID) -> bool:
        return self._guid_bytes_le(a) == self._guid_bytes_le(b)

    def query_interface(self, this_ptr, iid_ptr, obj_ptr):
        iid = iid_ptr.contents
        if TRACE_ENABLED:
            try:
                import uuid
                guid_str = str(uuid.UUID(bytes_le=self._guid_bytes_le(iid))).upper()
                gdb.write(f"QueryInterface called for IID {guid_str}\n")
            except Exception:
                pass

        if self._guid_equal(iid, IID_IUnknown) or self._guid_equal(iid, IID_IDebuggerServices):
            obj_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> IDebuggerServices\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_IMemoryService):
            obj_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> IMemoryService\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_IHost):
            obj_ptr.contents.value = ctypes.addressof(self.ihost_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> IHost\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_ILLDBServices):
            obj_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> ILLDBServices (stub)\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_ILLDBServices2):
            obj_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> ILLDBServices2 (stub)\n")
            self.add_ref(this_ptr)
            return 0
        obj_ptr.contents.value = 0
        if TRACE_ENABLED:
            gdb.write("QI -> E_NOINTERFACE\n")
        return 0x80004002

    def add_ref(self, this_ptr):
        self._ref += 1
        return self._ref

    def release(self, this_ptr):
        self._ref -= 1
        return self._ref

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
                    path_field = ' '.join(parts[5:])
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
                        if start < base:
                            base = start
            if found_path:
                self._coreclr_path = found_path
                self._coreclr_base = base
                directory = os.path.dirname(found_path)
                if directory:
                    path_bytes = directory.encode('utf-8')
                    self._coreclr_dir_buf = ctypes.create_string_buffer(path_bytes + b"\x00")
                trace(f"_scan_coreclr found path={self._coreclr_path} base=0x{self._coreclr_base:x}")
                return self._coreclr_path, self._coreclr_base
        except Exception as ex:
            trace(f"_scan_coreclr error: {ex}")
        self._coreclr_path = None
        self._coreclr_base = None
        self._coreclr_dir_buf = None
        return None, None

    # --- IMemoryService ---
    def read_virtual(self, this_ptr, address, buffer, bytes_requested, bytes_read_ptr):
        trace("call into read_virtual")
        try:
            inferior = gdb.selected_inferior()
            mem = inferior.read_memory(address, bytes_requested)
            bytes_read = len(mem)
            ctypes.memmove(buffer, mem.tobytes(), bytes_read)
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = bytes_read
            return 0
        except gdb.MemoryError:
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = 0
            return 0x80070005

    # --- IHost ---
    def host_get_host_type(self, this_ptr):
        trace("call into host_get_host_type")
        return 0

    def host_get_service(self, this_ptr, guid_ptr, out_ptr):
        trace("call into host_get_service")
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

        if guid_ptr:
            iid = guid_ptr.contents
            if self._guid_equal(iid, IID_ILLDBServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_ILLDBServices2):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_IHostServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.ihostservices_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_IDebuggerServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_IMemoryService):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
                self.add_ref(this_ptr)
                return 0

        return 0x80004002

    def host_get_current_target(self, this_ptr, out_ptr):
        trace("call into host_get_current_target")
        if out_ptr:
            out_ptr.contents.value = 0
        return 0x80004001

    # --- IHostServices ---
    def hostservices_get_host(self, this_ptr, ppHost):
        trace("call into hostservices_get_host (disabled)")
        if ppHost:
            ppHost.contents.value = 0
        return 0x80004002

    def hostservices_register_debugger_services(self, this_ptr, iunk):
        trace("call into hostservices_register_debugger_services")
        self._registered_debugger = iunk
        return 0

    def hostservices_create_target(self, this_ptr):
        trace("call into hostservices_create_target")
        return 0

    def hostservices_update_target(self, this_ptr, processId):
        trace(f"call into hostservices_update_target pid={processId}")
        return 0

    def hostservices_flush_target(self, this_ptr):
        trace("call into hostservices_flush_target")

    def hostservices_destroy_target(self, this_ptr):
        trace("call into hostservices_destroy_target")

    def hostservices_dispatch_command(self, this_ptr, commandName, arguments, displayCommandNotFound):
        try:
            cn = commandName.decode() if commandName else None
            args = arguments.decode() if arguments else None
            trace(f"call into hostservices_dispatch_command cmd={cn} args={args} displayCNF={bool(displayCommandNotFound)}")
        except Exception:
            trace("call into hostservices_dispatch_command")
        return 0x80004001

    def hostservices_uninitialize(self, this_ptr):
        trace("call into hostservices_uninitialize")

    # --- ILLDBServices2 ---
    def lldb2_load_native_symbols(self, this_ptr, runtimeOnly, callback):
        trace("call into lldb2_load_native_symbols")
        return 0

    def lldb2_add_module_symbol(self, this_ptr, param, symbolFilePath):
        trace("call into lldb2_add_module_symbol")
        return 0

    def lldb2_get_module_info(self, this_ptr, index, moduleBase, moduleSize, timestamp, checksum):
        trace(f"call into lldb2_get_module_info index={index}")
        if index != 0:
            return 0x80004005
        path, base_addr = self._scan_coreclr()
        if not path or base_addr is None:
            return 0x80004005
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
            trace(f"GetModuleInfo maps scan error: {ex}")

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
        trace(f"  -> base=0x{base_addr:x} size=0x{size_val:x}")
        return 0

    def lldb2_get_module_version_information(self, this_ptr, index, base, item, buffer, bufferSize, versionInfoSize):
        trace("call into lldb2_get_module_version_information")
        return 0x80004001

    def lldb2_set_runtime_loaded_callback(self, this_ptr, callback):
        trace("call into lldb2_set_runtime_loaded_callback")
        return 0

    # --- ILLDBServices ---
    def lldb_get_coreclr_directory(self, this_ptr):
        trace("call into lldb_get_coreclr_directory")
        try:
            path, base = self._scan_coreclr()
            if path and self._coreclr_dir_buf:
                trace(f"coreclr directory: {os.path.dirname(path)} base=0x{base:x}")
                return ctypes.cast(self._coreclr_dir_buf, ctypes.c_char_p)
        except Exception as ex:
            trace(f"lldb_get_coreclr_directory error: {ex}")
        trace("coreclr directory: NOT FOUND")
        return None

    def lldb_get_expression(self, this_ptr, exp):
        trace("call into lldb_get_expression")
        try:
            expr = exp.decode() if isinstance(exp, (bytes, bytearray)) else exp
            val = gdb.parse_and_eval(expr)
            try:
                return int(val)
            except Exception:
                try:
                    return int(val.cast(gdb.lookup_type('unsigned long long')))
                except Exception:
                    return 0
        except Exception:
            return 0

    def lldb_virtual_unwind(self, this_ptr, threadID, contextSize, context):
        trace("call into lldb_virtual_unwind")
        return 0x80004001

    def lldb_set_exception_callback(self, this_ptr, cb):
        trace("call into lldb_set_exception_callback")
        return 0

    def lldb_clear_exception_callback(self, this_ptr):
        trace("call into lldb_clear_exception_callback")
        return 0

    def lldb_get_interrupt(self, this_ptr):
        trace("call into lldb_get_interrupt")
        return 1

    def lldb_output_va_list(self, this_ptr, mask, fmt, va_list_ptr):
        trace("call into lldb_output_va_list")
        try:
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
            size = 1024
            while True:
                buf = ctypes.create_string_buffer(size)
                written = vsnprintf(buf, size, fmt, va_list_ptr)
                if written < 0:
                    break
                if written >= size:
                    size = written + 1
                    buf = ctypes.create_string_buffer(size)
                    vsnprintf(buf, size, fmt, va_list_ptr)
                try:
                    gdb.write(buf.value.decode(errors='replace'))
                except Exception:
                    import sys
                    sys.stdout.write(buf.value.decode(errors='replace'))
                break
        except Exception:
            pass
        return 0

    def lldb_get_debuggee_type(self, this_ptr, debugClass, qualifier):
        trace("call into lldb_get_debuggee_type")
        if debugClass:
            debugClass.contents.value = DEBUG_CLASS_USER_WINDOWS
        if qualifier:
            qualifier.contents.value = DEBUG_DUMP_FULL
        return 0

    def lldb_get_page_size(self, this_ptr, size_ptr):
        trace("call into lldb_get_page_size")
        if size_ptr:
            size_ptr.contents.value = 4096
        return 0

    def lldb_get_processor_type(self, this_ptr, type_ptr):
        trace("call into lldb_get_processor_type")
        if type_ptr:
            type_ptr.contents.value = IMAGE_FILE_MACHINE_AMD64
        return 0

    def lldb_execute(self, this_ptr, outctl, command, flags):
        trace("call into lldb_execute")
        try:
            cmd = command.decode() if command else ""
            if cmd and TRACE_ENABLED:
                gdb.write(f"[ILLDBServices.Execute] {cmd}\n")
        except Exception:
            pass
        return 0

    def lldb_get_last_event_information(self, this_ptr, t, pid, tid, extra, extraSize, extraUsed, desc, descSize, descUsed):
        trace("call into lldb_get_last_event_information")
        if t: t.contents.value = 0
        if pid: pid.contents.value = 0
        if tid: tid.contents.value = 0
        if extraUsed: extraUsed.contents.value = 0
        if descUsed: descUsed.contents.value = 0
        return 0

    def lldb_disassemble(self, this_ptr, offset, flags, buffer, bufferSize, disSize, endOffset):
        trace("call into lldb_disassemble")
        return 0x80004001

    def lldb_get_context_stack_trace(self, this_ptr, startContext, startContextSize, frames, framesSize, frameContexts, frameContextsSize, frameContextsEntrySize, framesFilled):
        trace("call into lldb_get_context_stack_trace")
        return 0x80004001

    def lldb_read_virtual(self, this_ptr, address, buffer, bufferSize, bytesRead):
        trace("call into lldb_read_virtual")
        return self.read_virtual(this_ptr, address, buffer, bufferSize, bytesRead)

    def lldb_write_virtual(self, this_ptr, address, buffer, bufferSize, bytesWritten):
        trace("call into lldb_write_virtual")
        return 0x80004001

    def lldb_get_symbol_options(self, this_ptr, options):
        trace("call into lldb_get_symbol_options")
        return 0x80004001

    def lldb_get_name_by_offset(self, this_ptr, offset, nameBuffer, nameBufferSize, nameSize, displacement):
        trace("call into lldb_get_name_by_offset")
        return 0x80004001

    def lldb_get_number_modules(self, this_ptr, loaded, unloaded):
        trace("call into lldb_get_number_modules")
        path, _ = self._scan_coreclr()
        if loaded:
            loaded.contents.value = 1 if path else 0
        if unloaded:
            unloaded.contents.value = 0
        trace(f"  -> loaded={loaded.contents.value if loaded else 'n/a'} unloaded={unloaded.contents.value if unloaded else 'n/a'} path={path}")
        return 0

    def lldb_get_module_by_index(self, this_ptr, index, base):
        trace(f"call into lldb_get_module_by_index index={index}")
        _, coreclr_base = self._scan_coreclr()
        if index == 0 and coreclr_base is not None:
            if base:
                base.contents.value = ctypes.c_uint64(coreclr_base).value
            trace(f"  -> base=0x{coreclr_base:x}")
            return 0
        return 0x80004005

    def lldb_get_module_by_module_name(self, this_ptr, name, startIndex, index, base):
        try:
            q = name.decode() if name else ""
        except Exception:
            q = ""
        trace(f"call into lldb_get_module_by_module_name name='{q}' startIndex={startIndex}")
        path, coreclr_base = self._scan_coreclr()
        if coreclr_base is None:
            return 0x80004005
        base_name = os.path.basename(path)
        if startIndex > 0:
            return 0x80004005
        if not q or q.lower() in base_name.lower():
            if index:
                index.contents.value = 0
            if base:
                base.contents.value = ctypes.c_uint64(coreclr_base).value
            trace(f"  -> index=0 base=0x{coreclr_base:x}")
            return 0
        return 0x80004005

    def lldb_get_module_by_offset(self, this_ptr, offset, startIndex, index, base):
        trace("call into lldb_get_module_by_offset")
        return 0x80004001

    def lldb_get_module_names(self, this_ptr, index, base, imageNameBuffer, imageNameBufferSize, imageNameSize, moduleNameBuffer, moduleNameBufferSize, moduleNameSize, loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize):
        trace(f"call into lldb_get_module_names index={index} base={base}")
        path, coreclr_base = self._scan_coreclr()
        if not path:
            return 0x80004005
        if index != 0:
            if index != DEBUG_ANY_ID:
                return 0x80004005
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
                char_p = ctypes.cast(buf_voidp, ctypes.POINTER(ctypes.c_char))
                n = min(len(data_bytes), max(0, bufSize - 1))
                if n > 0:
                    ctypes.memmove(char_p, data_bytes, n)
                try:
                    char_p[n] = b"\x00"
                except Exception:
                    zero = (ctypes.c_char * 1)()
                    ctypes.memmove(ctypes.cast(ctypes.addressof(char_p.contents) + n, ctypes.c_void_p), zero, 1)
            except Exception as ex:
                trace(f"lldb_get_module_names.fill error: {ex}")

        fill(imageNameBuffer, imageNameBufferSize, imageNameSize, img)
        fill(moduleNameBuffer, moduleNameBufferSize, moduleNameSize, name)
        fill(loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize, img)
        return 0

    def lldb_get_line_by_offset(self, this_ptr, offset, line, fileBuffer, fileBufferSize, fileSize, displacement):
        trace("call into lldb_get_line_by_offset")
        return 0x80004001

    def lldb_get_source_file_line_offsets(self, this_ptr, file, buffer, bufferLines, fileLines):
        trace("call into lldb_get_source_file_line_offsets")
        return 0x80004001

    def lldb_find_source_file(self, this_ptr, startElement, file, flags, foundElement, buffer, bufferSize, foundSize):
        trace("call into lldb_find_source_file")
        return 0x80004001

    def lldb_get_current_process_system_id(self, this_ptr, id_ptr):
        trace("call into lldb_get_current_process_system_id")
        if id_ptr:
            pid = self._get_pid() or 0
            id_ptr.contents.value = pid
        return 0

    def lldb_get_current_thread_id(self, this_ptr, id_ptr):
        trace("call into lldb_get_current_thread_id")
        if id_ptr:
            id_ptr.contents.value = 0
        return 0

    def lldb_set_current_thread_id(self, this_ptr, id_value):
        trace("call into lldb_set_current_thread_id")
        return 0

    def lldb_get_current_thread_system_id(self, this_ptr, sysId):
        trace("call into lldb_get_current_thread_system_id")
        if sysId:
            sysId.contents.value = 0
        return 0

    def lldb_get_thread_id_by_system_id(self, this_ptr, sysId, id_ptr):
        trace("call into lldb_get_thread_id_by_system_id")
        return 0x80004001

    def lldb_get_thread_context_by_system_id(self, this_ptr, sysId, contextFlags, contextSize, context):
        trace("call into lldb_get_thread_context_by_system_id")
        return 0x80004001

    def lldb_get_value_by_name(self, this_ptr, name, value_ptr):
        trace("call into lldb_get_value_by_name")
        return 0x80004001

    def lldb_get_instruction_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_instruction_offset")
        return 0x80004001

    def lldb_get_stack_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_stack_offset")
        return 0x80004001

    def lldb_get_frame_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_frame_offset")
        return 0x80004001

    # --- IDebuggerServices ---
    def dbg_get_operating_system(self, this_ptr, os_ptr):
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
        _, base = self._scan_coreclr()
        if index != 0 or base is None:
            return 0x80004005
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
                addr = buf_voidp if isinstance(buf_voidp, int) else ctypes.cast(buf_voidp, ctypes.c_void_p).value
                if not addr:
                    return
                n = min(len(data_bytes), max(0, bufSize - 1))
                if n > 0:
                    ctypes.memmove(addr, data_bytes, n)
                ctypes.memmove(addr + n, b"\x00", 1)
            except Exception as ex:
                trace(f"dbg_get_module_names.fill error: {ex}")
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
        if enabled_ptr:
            enabled_ptr.contents.value = 0
        return 0
