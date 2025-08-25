#ifndef __GDB_COMMAND_H__
#define __GDB_COMMAND_H__

// This function is called from the main plugin entry point (_initialize_gdbplugin)
// to register all the SOS commands with GDB.
void InitializeSOSCommands();

#endif // __GDB_COMMAND_H__