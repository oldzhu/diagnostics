#ifndef __GDB_SERVICES_H__
#define __GDB_SERVICES_H__

#include "debuggerservices.h"

// This class implements the debugger-agnostic interfaces from debuggerservices.h
// using GDB's C/C++ API. For simplicity in the POC, it implements the memory
// service interface directly.
class GDBDebuggerServices : public IDebuggerServices,
                            public IMemoryService
{
public:
    GDBDebuggerServices() {}
    virtual ~GDBDebuggerServices() {}

    //
    // IUnknown
    //
    STDMETHOD(QueryInterface)(REFIID riid, PVOID* ppvObject);
    STDMETHOD_(ULONG, AddRef)();
    STDMETHOD_(ULONG, Release)();

    //
    // IDebuggerServices
    //
    virtual HRESULT GetMemoryService(IMemoryService** ppMemoryService);
    virtual HRESULT GetThreadService(IThreadService** ppThreadService) { return E_NOTIMPL; }
    virtual HRESULT GetSymbolService(ISymbolService** ppSymbolService) { return E_NOTIMPL; }
    virtual HRESULT GetRuntimeService(IRuntimeService** ppRuntimeService) { return E_NOTIMPL; }
    virtual HRESULT GetCommandService(ICommandService** ppCommandService) { return E_NOTIMPL; }
    virtual HRESULT GetHostService(IHostService** ppHostService) { return E_NOTIMPL; }
    virtual HRESULT GetDisassemblyService(IDisassemblyService** ppDisassemblyService) { return E_NOTIMPL; }
    virtual HRESULT GetUtilityService(IUtilityService** ppUtilityService) { return E_NOTIMPL; }
    virtual HRESULT GetTarget(ITarget** ppTarget) { return E_NOTIMPL; }

    //
    // IMemoryService
    //
    virtual HRESULT ReadVirtual(ULONG64 address, PVOID buffer, ULONG32 bytesRequested, PULONG32 pbytesRead);
    virtual HRESULT WriteVirtual(ULONG64 address, PVOID buffer, ULONG32 bytesRequested, PULONG32 pbytesWritten) { return E_NOTIMPL; }

private:
    LONG m_ref = 1;
};

#endif // __GDB_SERVICES_H__