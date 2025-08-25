#include <dlfcn.h>
#include "services.h"
#include "gdbcommand.h"

// The global instance of our GDB services implementation.
// The core SOS library will use this to interact with GDB.
GDBDebuggerServices g_services;

// A handle to the dynamically loaded core SOS library (libsos.so).
void* g_sosHandle = nullptr;

// GDB requires a specific function name to initialize the plugin.
// It's a C-style function: _initialize_<plugin_name_without_so>
extern "C" void _initialize_gdbplugin()
{
    // This is the main entry point called by GDB.
    // We delegate the command registration to a separate function
    // to keep this entry point clean.
    InitializeSOSCommands();
}