#include <gdb/gdb-api.h>
#include <dlfcn.h>
#include <stdio.h>
#include "gdbcommand.h"
#include "services.h"
#include "pal.h" // For SOS_FUNCTION definition

// These are defined in gdbplugin.cpp
extern void* g_sosHandle;
extern GDBDebuggerServices g_services;

// Helper to load the core SOS library (libsos.so) and initialize it.
static bool LoadSos()
{
    if (g_sosHandle != nullptr) {
        return true;
    }

    // For the POC, we assume libsos.so is in a standard search path.
    // A real implementation would need a more robust discovery mechanism.
    const char* sosLibraryName = "libsos.so";
    g_sosHandle = dlopen(sosLibraryName, RTLD_LAZY);

    if (g_sosHandle == nullptr) {
        gdb::error("Failed to load SOS library '%s'. Error: %s", sosLibraryName, dlerror());
        return false;
    }

    // After loading, SOS must be initialized with our GDB services implementation.
    typedef HRESULT (*InitializeForDebuggerServices)(IDebuggerServices*);
    auto initFunc = (InitializeForDebuggerServices)dlsym(g_sosHandle, "InitializeForDebuggerServices");
    if (initFunc == nullptr) {
        gdb::error("Failed to find InitializeForDebuggerServices in SOS library.");
        dlclose(g_sosHandle);
        g_sosHandle = nullptr;
        return false;
    }

    if (FAILED(initFunc(&g_services))) {
        gdb::error("InitializeForDebuggerServices failed.");
        dlclose(g_sosHandle);
        g_sosHandle = nullptr;
        return false;
    }
    return true;
}

// This class represents a generic SOS command registered with GDB.
class SOSCommand : public gdb::command
{
public:
    SOSCommand(const char* name) : gdb::command(name, gdb::COMMAND_DATA, gdb::COMPLETE_NONE)
    {
        m_name = name;
    }

protected:
    void invoke(const gdb::string_view &args, bool from_tty) override
    {
        if (!LoadSos()) {
            return; // Error already printed by LoadSos
        }

        // Find the function in libsos.so corresponding to the command name.
        SOS_FUNCTION sosFunc = (SOS_FUNCTION)dlsym(g_sosHandle, m_name);
        if (sosFunc == nullptr) {
            gdb::error("Command '%s' not found in SOS library.", m_name);
            return;
        }

        // The core SOS functions expect a C-style string.
        std::string args_str(args);

        // Execute the SOS command.
        HRESULT hr = sosFunc(&g_services, args_str.c_str());
        if (FAILED(hr)) {
            gdb::warning("Command '%s' failed with HRESULT 0x%lx", m_name, hr);
        }
    }

private:
    const char* m_name;
};

// Create static instances of each command we want to support.
// GDB's framework will automatically register them.
static SOSCommand dumpobj_command("dumpobj");
// To add more commands, simply add a new line here:
// static SOSCommand clrstack_command("clrstack");
// static SOSCommand threads_command("threads");

// This function is called by the plugin entry point.
void InitializeSOSCommands()
{
    // The static command instances above are automatically registered
    // by their constructors, so this function can be empty. It just
    // ensures the static initializers have run.
    gdb::printf("SOS GDB extension loaded. Use 'dumpobj <address>' for .NET object inspection.\n");
}