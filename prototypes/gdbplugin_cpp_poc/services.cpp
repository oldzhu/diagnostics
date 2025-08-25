#include <gdb/gdb-api.h>
#include "services.h"

// Standard IUnknown implementation
HRESULT GDBDebuggerServices::QueryInterface(REFIID riid, PVOID* ppvObject)
{
    if (riid == IID_IUnknown || riid == IID_IDebuggerServices)
    {
        *ppvObject = static_cast<IDebuggerServices*>(this);
    }
    else if (riid == IID_IMemoryService)
    {
        *ppvObject = static_cast<IMemoryService*>(this);
    }
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

ULONG GDBDebuggerServices::AddRef()
{
    return InterlockedIncrement(&m_ref);
}

ULONG GDBDebuggerServices::Release()
{
    LONG ref = InterlockedDecrement(&m_ref);
    if (ref == 0) {
        delete this;
    }
    return ref;
}

// Gets the memory service interface.
HRESULT GDBDebuggerServices::GetMemoryService(IMemoryService** ppMemoryService)
{
    return QueryInterface(IID_IMemoryService, (PVOID*)ppMemoryService);
}

// Reads memory from the debugged process using the GDB API.
HRESULT GDBDebuggerServices::ReadVirtual(
    ULONG64 address,
    PVOID buffer,
    ULONG32 bytesRequested,
    PULONG32 pbytesRead)
{
    if (pbytesRead != nullptr) {
        *pbytesRead = 0;
    }

    if (buffer == nullptr) {
        return E_INVALIDARG;
    }

    // gdb::target_read_memory is the GDB API function to read from the inferior process.
    int bytesRead = gdb::target_read_memory(address, (gdb_byte*)buffer, bytesRequested);

    if (pbytesRead != nullptr) {
        *pbytesRead = bytesRead;
    }

    // If bytesRead is less than requested, it usually indicates an error (e.g., reading invalid memory).
    if (bytesRead < bytesRequested) {
        return E_FAIL;
    }

    return S_OK;
}