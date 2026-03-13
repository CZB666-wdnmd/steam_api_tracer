#pragma once
// ============================================================================
//  IPC / Callback Payload Dump Module
//  Captures Steam callback payloads and interface method calls
//  Does NOT hook any global Win32 APIs (safe, no side effects)
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Initialize dump module (call early in DllMain ATTACH)
void IpcDump_Init();

// Attach/Detach hooks within a Detours transaction
void IpcDump_AttachHooks();
void IpcDump_DetachHooks();

// Cleanup (call in DllMain DETACH)
void IpcDump_Shutdown();