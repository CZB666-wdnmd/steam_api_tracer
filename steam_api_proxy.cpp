// ============================================================================
//  Steam API Proxy DLL - Using Microsoft Detours + ASM forwarding thunks
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>

#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <string>

#include "data_exports.h"
#include "ipc_dump.h"

// ============================================================================
// Platform macros
// ============================================================================

#ifdef _MSC_VER
    #define FMT_U64 "%I64u"
#else
    #define FMT_U64 "%llu"
#endif

#define SAFE_STR(s) ((s) ? (s) : "(null)")

// ============================================================================
// Logging
// ============================================================================

static FILE*           g_LogFile    = nullptr;
static std::mutex      g_LogMutex;
static LARGE_INTEGER   g_StartTime  = {};
static LARGE_INTEGER   g_Frequency  = {};
static volatile bool   g_LogEnabled = false;
static constexpr long  LOG_MAX_SIZE = 50L * 1024 * 1024;
static long            g_LogWritten = 0;

static void InitLog()
{
#ifdef _MSC_VER
    errno_t err = fopen_s(&g_LogFile, "steam_api_trace.log", "w");
    if (err != 0) g_LogFile = nullptr;
#else
    g_LogFile = fopen("steam_api_trace.log", "w");
#endif

    QueryPerformanceFrequency(&g_Frequency);
    QueryPerformanceCounter(&g_StartTime);

    if (g_LogFile)
    {
        g_LogEnabled = true;
        fprintf(g_LogFile, "=== Steam API Trace Log (Detours Edition) ===\n");
        fprintf(g_LogFile, "Timestamp(ms) | Thread | Function | Details\n");
        fprintf(g_LogFile, "---------------------------------------------\n");
        fflush(g_LogFile);
    }
}

static void CloseLog()
{
    g_LogEnabled = false;
    std::lock_guard<std::mutex> lock(g_LogMutex);
    if (g_LogFile)
    {
        fflush(g_LogFile);
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }
}

void TraceLog(const char* fmt, ...)
{
    if (!g_LogEnabled || !g_LogFile) return;

    std::lock_guard<std::mutex> lock(g_LogMutex);
    if (!g_LogFile) return;

    if (g_LogWritten > LOG_MAX_SIZE)
    {
        if (g_LogWritten != LONG_MAX)
        {
            fprintf(g_LogFile, "\n[LOG TRUNCATED - exceeded %ld MB limit]\n",
                    LOG_MAX_SIZE / (1024 * 1024));
            fflush(g_LogFile);
            g_LogWritten = LONG_MAX;
        }
        return;
    }

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double ms = static_cast<double>(now.QuadPart - g_StartTime.QuadPart)
              * 1000.0 / static_cast<double>(g_Frequency.QuadPart);

    int written = fprintf(g_LogFile, "[%12.3f] [TID:%05lu] ", ms, GetCurrentThreadId());

    va_list args;
    va_start(args, fmt);
    written += vfprintf(g_LogFile, fmt, args);
    va_end(args);

    written += fprintf(g_LogFile, "\n");
    fflush(g_LogFile);

    if (written > 0) g_LogWritten += written;
}

// ============================================================================
// Original DLL handle - extern "C" so the ASM thunks can access it
// ============================================================================

extern "C" {
    HMODULE g_OriginalDll = nullptr;
}

static bool LoadOriginalDll()
{
    g_OriginalDll = LoadLibraryA("steam_api64_o.dll");
    if (g_OriginalDll)
        return true;

    char steamPath[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("SteamPath", steamPath, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
    {
        const char* suffix = "\\steam_api64.dll";
        if (len + strlen(suffix) < MAX_PATH)
        {
            strcat_s(steamPath, MAX_PATH, suffix);
            for (DWORD i = 0; steamPath[i]; ++i)
                if (steamPath[i] == '/') steamPath[i] = '\\';
            g_OriginalDll = LoadLibraryA(steamPath);
        }
    }
    return g_OriginalDll != nullptr;
}

// ============================================================================
// Resolve data exports
// ============================================================================

static void ResolveDataExports()
{
    if (!g_OriginalDll) return;

    for (int i = 0; i < g_NumDataExports; ++i)
    {
        void* origAddr = (void*)GetProcAddress(g_OriginalDll, g_DataExports[i].name);
        if (origAddr)
        {
            void* value = *(void**)origAddr;
            *(g_DataExports[i].pSlot) = value;
            TraceLog("  Data export: %s = %p (orig @ %p)",
                     g_DataExports[i].name, value, origAddr);
        }
        else
        {
            TraceLog("  Data export: %s = NOT FOUND", g_DataExports[i].name);
        }
    }
}

// ============================================================================
// Interface tracking system
// ============================================================================

// ifacePtr -> interface version name
static std::mutex                                       g_IfaceMapMutex;
static std::unordered_map<uintptr_t, std::string>       g_IfacePtrToName;

// ctxDataAddr -> resolved interface name
static std::mutex                                       g_CtxMapMutex;
static std::unordered_map<uintptr_t, std::string>       g_CtxDataToName;

// Set of ctxDataAddr values we've already logged (suppress repeated logs)
static std::unordered_set<uintptr_t>                    g_CtxLoggedOnce;

static const char* GetCallbackName(int id)
{
    switch (id)
    {
    case 101:  return "SteamServersConnected_t";
    case 102:  return "SteamServerConnectFailure_t";
    case 103:  return "SteamServersDisconnected_t";
    case 113:  return "ClientGameServerDeny_t";
    case 115:  return "IPCFailure_t";
    case 117:  return "LicensesUpdated_t";
    case 143:  return "GameLobbyJoinRequested_t";
    case 154:  return "GetAuthSessionTicketResponse_t";
    case 163:  return "ValidateAuthTicketResponse_t";
    case 164:  return "MicroTxnAuthorizationResponse_t";
    case 165:  return "EncryptedAppTicketResponse_t";
    case 166:  return "GetTicketForWebApiResponse_t";
    case 168:  return "GameRichPresenceJoinRequested_t";
    case 331:  return "FriendRichPresenceUpdate_t";
    case 332:  return "GameRichPresenceJoinRequested_t";
    case 333:  return "FavoritesListChanged_t";
    case 334:  return "FriendGameInfo_t";
    case 335:  return "ClanOfficerListResponse_t";
    case 336:  return "LobbyCreated_t";
    case 337:  return "LobbyEnter_t";
    case 338:  return "LobbyInvite_t";
    case 339:  return "FriendsGroupID_t";
    case 304:  return "LobbyDataUpdate_t";
    case 305:  return "LobbyChatUpdate_t";
    case 306:  return "LobbyChatMsg_t";
    case 309:  return "LobbyMatchList_t";
    case 512:  return "LobbyGameCreated_t";
    case 504:  return "P2PSessionRequest_t";
    case 505:  return "P2PSessionConnectFail_t";
    case 506:  return "SocketStatusCallback_t";
    case 704:  return "ScreenshotReady_t";
    case 1101: return "UserStatsReceived_t";
    case 1102: return "UserStatsStored_t";
    case 1103: return "UserAchievementStored_t";
    case 1108: return "UserStatsUnloaded_t";
    case 1109: return "UserAchievementIconFetched_t";
    case 1201: return "SteamNetworkingMessagesSessionRequest_t";
    case 1202: return "SteamNetConnectionStatusChangedCallback_t";
    case 1203: return "SteamNetAuthenticationStatus_t";
    case 1221: return "SteamRelayNetworkStatus_t";
    case 1307: return "RemoteStoragePublishFileProgress_t";
    case 1309: return "RemoteStoragePublishedFileUpdated_t";
    case 3401: return "SteamUGCQueryCompleted_t";
    case 3402: return "SteamUGCRequestUGCDetailsResult_t";
    case 3403: return "CreateItemResult_t";
    case 3404: return "SubmitItemUpdateResult_t";
    case 3405: return "ItemInstalled_t";
    case 3406: return "DownloadItemResult_t";
    default:   return nullptr;
    }
}

static void RegisterIfaceMapping(void* ptr, const char* name)
{
    if (!ptr || !name) return;
    std::lock_guard<std::mutex> lock(g_IfaceMapMutex);
    g_IfacePtrToName[reinterpret_cast<uintptr_t>(ptr)] = name;
}

static const char* LookupIfaceName(uintptr_t ptr)
{
    std::lock_guard<std::mutex> lock(g_IfaceMapMutex);
    auto it = g_IfacePtrToName.find(ptr);
    return (it != g_IfacePtrToName.end()) ? it->second.c_str() : nullptr;
}

// ============================================================================
// Safe memory read helper - isolated in its own function so __try/__except
// doesn't conflict with C++ objects that need unwinding.
// ============================================================================

// Reads a QWORD at the given address; returns 0 on access violation.
static uintptr_t SafeReadQword(uintptr_t addr)
{
    uintptr_t value = 0;
    __try
    {
        value = *reinterpret_cast<uintptr_t*>(addr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        value = 0;
    }
    return value;
}

// ============================================================================
// Original function pointers
// ============================================================================

typedef bool     (*FnBoolVoid)();
typedef int      (*FnInitFlat)(char*, int);
typedef void     (*FnVoidVoid)();
typedef bool     (*FnRestartApp)(uint32_t);
typedef void*    (*FnCreateInterface)(const char*);
typedef void*    (*FnFindOrCreateUser)(int32_t, const char*);
typedef void*    (*FnFindOrCreateGS)(int32_t, const char*);
typedef void*    (*FnContextInit)(void*);
typedef int32_t  (*FnGetHandle)();
typedef void     (*FnRegisterCb)(void*, int);
typedef void     (*FnUnregisterCb)(void*);
typedef void     (*FnRegisterCr)(void*, uint64_t);
typedef void     (*FnUnregisterCr)(void*, uint64_t);

static FnBoolVoid           Real_SteamAPI_Init                              = nullptr;
static FnBoolVoid           Real_SteamAPI_InitSafe                          = nullptr;
static FnInitFlat           Real_SteamAPI_InitFlat                          = nullptr;
static FnVoidVoid           Real_SteamAPI_Shutdown                          = nullptr;
static FnRestartApp         Real_SteamAPI_RestartAppIfNecessary             = nullptr;
static FnVoidVoid           Real_SteamAPI_RunCallbacks                      = nullptr;
static FnBoolVoid           Real_SteamAPI_IsSteamRunning                    = nullptr;
static FnCreateInterface    Real_SteamInternal_CreateInterface              = nullptr;
static FnFindOrCreateUser   Real_SteamInternal_FindOrCreateUserInterface    = nullptr;
static FnFindOrCreateGS     Real_SteamInternal_FindOrCreateGameServerInterface = nullptr;
static FnContextInit        Real_SteamInternal_ContextInit                  = nullptr;
static FnGetHandle          Real_SteamAPI_GetHSteamPipe                     = nullptr;
static FnGetHandle          Real_SteamAPI_GetHSteamUser                     = nullptr;
static FnRegisterCb         Real_SteamAPI_RegisterCallback                  = nullptr;
static FnUnregisterCb       Real_SteamAPI_UnregisterCallback                = nullptr;
static FnRegisterCr         Real_SteamAPI_RegisterCallResult                = nullptr;
static FnUnregisterCr       Real_SteamAPI_UnregisterCallResult              = nullptr;

// ============================================================================
// GetProcAddress Hook
// ============================================================================

static std::unordered_map<std::string, FARPROC> g_InterceptedFunctions;

static decltype(&GetProcAddress) Real_GetProcAddress = GetProcAddress;

static FARPROC WINAPI Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if (hModule == g_OriginalDll && lpProcName != nullptr && !IS_INTRESOURCE(lpProcName))
    {
        auto it = g_InterceptedFunctions.find(lpProcName);
        if (it != g_InterceptedFunctions.end())
        {
            TraceLog("[LazyResolve] INTERCEPTED: \"%s\" -> proxy", lpProcName);
            return it->second;
        }

        FARPROC result = Real_GetProcAddress(hModule, lpProcName);
        TraceLog("[LazyResolve] FORWARDED: \"%s\" -> %p", lpProcName, result);
        return result;
    }

    return Real_GetProcAddress(hModule, lpProcName);
}

// ============================================================================
// Intercepted API functions
// ============================================================================

extern "C" {

__declspec(dllexport) bool SteamAPI_Init()
{
    TraceLog("[SteamAPI_Init] >>> calling");
    bool result = Real_SteamAPI_Init ? Real_SteamAPI_Init() : false;
    TraceLog("[SteamAPI_Init] <<< result=%s", result ? "true" : "false");
    return result;
}

__declspec(dllexport) bool SteamAPI_InitSafe()
{
    TraceLog("[SteamAPI_InitSafe] >>> calling");
    bool result = Real_SteamAPI_InitSafe ? Real_SteamAPI_InitSafe() : false;
    TraceLog("[SteamAPI_InitSafe] <<< result=%s", result ? "true" : "false");
    return result;
}

__declspec(dllexport) int SteamAPI_InitFlat(char* pOutErrMsg, int cbErrMsg)
{
    TraceLog("[SteamAPI_InitFlat] >>> buf=%p, size=%d", pOutErrMsg, cbErrMsg);
    int result = Real_SteamAPI_InitFlat ? Real_SteamAPI_InitFlat(pOutErrMsg, cbErrMsg) : -1;
    TraceLog("[SteamAPI_InitFlat] <<< result=%d, msg=\"%s\"",
             result, (pOutErrMsg && pOutErrMsg[0]) ? pOutErrMsg : "");
    return result;
}

__declspec(dllexport) void SteamAPI_Shutdown()
{
    TraceLog("[SteamAPI_Shutdown] >>> calling");
    if (Real_SteamAPI_Shutdown) Real_SteamAPI_Shutdown();
    TraceLog("[SteamAPI_Shutdown] <<< done");
}

__declspec(dllexport) bool SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID)
{
    TraceLog("[SteamAPI_RestartAppIfNecessary] >>> AppID=%u", unOwnAppID);
    bool result = Real_SteamAPI_RestartAppIfNecessary
                  ? Real_SteamAPI_RestartAppIfNecessary(unOwnAppID) : false;
    TraceLog("[SteamAPI_RestartAppIfNecessary] <<< result=%s",
             result ? "true(restart)" : "false(ok)");
    return result;
}

static volatile long g_RunCallbacksCount = 0;

__declspec(dllexport) void SteamAPI_RunCallbacks()
{
    if (Real_SteamAPI_RunCallbacks) Real_SteamAPI_RunCallbacks();
    long count = InterlockedIncrement(&g_RunCallbacksCount);
    if (count == 1 || count % 1000 == 0)
        TraceLog("[SteamAPI_RunCallbacks] call #%ld", count);
}

__declspec(dllexport) bool SteamAPI_IsSteamRunning()
{
    bool result = Real_SteamAPI_IsSteamRunning ? Real_SteamAPI_IsSteamRunning() : false;
    TraceLog("[SteamAPI_IsSteamRunning] result=%s", result ? "true" : "false");
    return result;
}

__declspec(dllexport) void* SteamInternal_CreateInterface(const char* ver)
{
    TraceLog("[SteamInternal_CreateInterface] >>> version=\"%s\"", SAFE_STR(ver));
    void* result = Real_SteamInternal_CreateInterface
                   ? Real_SteamInternal_CreateInterface(ver) : nullptr;
    if (ver && result) RegisterIfaceMapping(result, ver);
    TraceLog("[SteamInternal_CreateInterface] <<< \"%s\" = %p", SAFE_STR(ver), result);
    return result;
}

__declspec(dllexport) void* SteamInternal_FindOrCreateUserInterface(
    int32_t hSteamUser, const char* ver)
{
    TraceLog("[SteamInternal_FindOrCreateUserInterface] >>> user=%d, version=\"%s\"",
             hSteamUser, SAFE_STR(ver));

    void* result = Real_SteamInternal_FindOrCreateUserInterface
                   ? Real_SteamInternal_FindOrCreateUserInterface(hSteamUser, ver) : nullptr;

    if (ver && result) RegisterIfaceMapping(result, ver);

    TraceLog("[SteamInternal_FindOrCreateUserInterface] <<< \"%s\" = %p%s",
             SAFE_STR(ver), result, result ? "" : " [FAILED]");
    return result;
}

__declspec(dllexport) void* SteamInternal_FindOrCreateGameServerInterface(
    int32_t hSteamUser, const char* ver)
{
    TraceLog("[SteamInternal_FindOrCreateGameServerInterface] >>> user=%d, version=\"%s\"",
             hSteamUser, SAFE_STR(ver));

    void* result = Real_SteamInternal_FindOrCreateGameServerInterface
                   ? Real_SteamInternal_FindOrCreateGameServerInterface(hSteamUser, ver) : nullptr;

    if (ver)
    {
        std::string gsName = std::string("GameServer:") + ver;
        if (result) RegisterIfaceMapping(result, gsName.c_str());
    }

    TraceLog("[SteamInternal_FindOrCreateGameServerInterface] <<< \"%s\" = %p%s",
             SAFE_STR(ver), result, result ? "" : " [NULL]");
    return result;
}

// ----------------------------------------------------------------------------
// SteamInternal_ContextInit
//
// Steamworks SDK ContextInitData layout (x64):
//   offset 0: void* (*pFn)(void*)   — init function pointer
//   offset 8: void* pCachedResult   — cached interface pointer
//
// ContextInit checks pCachedResult; if null, calls pFn to fill it.
// Returns pCachedResult either way.
//
// We identify the context by reverse-looking-up the returned pointer
// (or the cached pointer at offset+8) in our ifacePtr->name map.
// Once identified, we cache the mapping and suppress future log lines.
// ----------------------------------------------------------------------------

__declspec(dllexport) void* SteamInternal_ContextInit(void* pContextInitData)
{
    uintptr_t dataAddr = reinterpret_cast<uintptr_t>(pContextInitData);

    // Call the original
    void* result = Real_SteamInternal_ContextInit
                   ? Real_SteamInternal_ContextInit(pContextInitData) : nullptr;

    // Fast path: already known & already logged -> silent return
    {
        std::lock_guard<std::mutex> lock(g_CtxMapMutex);
        if (g_CtxLoggedOnce.count(dataAddr))
            return result;
    }

    // Try to identify this context
    const char* ctxName = nullptr;

    // Check if we already named this dataAddr (from a previous call)
    {
        std::lock_guard<std::mutex> lock(g_CtxMapMutex);
        auto it = g_CtxDataToName.find(dataAddr);
        if (it != g_CtxDataToName.end())
            ctxName = it->second.c_str();
    }

    // If not yet named, try the returned pointer
    if (!ctxName && result)
    {
        const char* ifaceName = LookupIfaceName(reinterpret_cast<uintptr_t>(result));
        if (ifaceName)
        {
            std::lock_guard<std::mutex> lock(g_CtxMapMutex);
            g_CtxDataToName[dataAddr] = ifaceName;
            ctxName = g_CtxDataToName[dataAddr].c_str();
        }
    }

    // If still unnamed, try reading the cached pointer at dataAddr+8
    if (!ctxName)
    {
        uintptr_t cachedPtr = SafeReadQword(dataAddr + 8);
        if (cachedPtr)
        {
            const char* ifaceName = LookupIfaceName(cachedPtr);
            if (ifaceName)
            {
                std::lock_guard<std::mutex> lock(g_CtxMapMutex);
                g_CtxDataToName[dataAddr] = ifaceName;
                ctxName = g_CtxDataToName[dataAddr].c_str();
            }
        }
    }

    // Log first occurrence
    if (ctxName)
    {
        TraceLog("[SteamInternal_ContextInit] [%s] data=%p -> %p",
                 ctxName, pContextInitData, result);
    }
    else
    {
        TraceLog("[SteamInternal_ContextInit] [ctx:0x%llX] data=%p -> %p",
                 (unsigned long long)dataAddr, pContextInitData, result);
    }

    // Mark as logged - suppress all future repeats for this dataAddr
    {
        std::lock_guard<std::mutex> lock(g_CtxMapMutex);
        g_CtxLoggedOnce.insert(dataAddr);
    }

    return result;
}

__declspec(dllexport) int32_t SteamAPI_GetHSteamPipe()
{
    int32_t result = Real_SteamAPI_GetHSteamPipe ? Real_SteamAPI_GetHSteamPipe() : 0;
    TraceLog("[SteamAPI_GetHSteamPipe] result=%d", result);
    return result;
}

__declspec(dllexport) int32_t SteamAPI_GetHSteamUser()
{
    int32_t result = Real_SteamAPI_GetHSteamUser ? Real_SteamAPI_GetHSteamUser() : 0;
    TraceLog("[SteamAPI_GetHSteamUser] result=%d", result);
    return result;
}

__declspec(dllexport) void SteamAPI_RegisterCallback(void* pCallback, int iCallback)
{
    const char* cbName = GetCallbackName(iCallback);
    if (cbName)
        TraceLog("[SteamAPI_RegisterCallback] cb=%p, id=%d (%s)", pCallback, iCallback, cbName);
    else
        TraceLog("[SteamAPI_RegisterCallback] cb=%p, id=%d (unknown)", pCallback, iCallback);
    if (Real_SteamAPI_RegisterCallback) Real_SteamAPI_RegisterCallback(pCallback, iCallback);
}

__declspec(dllexport) void SteamAPI_UnregisterCallback(void* pCallback)
{
    TraceLog("[SteamAPI_UnregisterCallback] cb=%p", pCallback);
    if (Real_SteamAPI_UnregisterCallback) Real_SteamAPI_UnregisterCallback(pCallback);
}

__declspec(dllexport) void SteamAPI_RegisterCallResult(void* pCallback, uint64_t hAPICall)
{
    TraceLog("[SteamAPI_RegisterCallResult] cb=%p, call=" FMT_U64, pCallback, hAPICall);
    if (Real_SteamAPI_RegisterCallResult) Real_SteamAPI_RegisterCallResult(pCallback, hAPICall);
}

__declspec(dllexport) void SteamAPI_UnregisterCallResult(void* pCallback, uint64_t hAPICall)
{
    TraceLog("[SteamAPI_UnregisterCallResult] cb=%p, call=" FMT_U64, pCallback, hAPICall);
    if (Real_SteamAPI_UnregisterCallResult) Real_SteamAPI_UnregisterCallResult(pCallback, hAPICall);
}

} // extern "C"

// ============================================================================
// Init helpers
// ============================================================================

#define RESOLVE(funcName, type) \
    Real_##funcName = reinterpret_cast<type>(GetProcAddress(g_OriginalDll, #funcName))

static void ResolveOriginalFunctions()
{
    if (!g_OriginalDll) return;
    RESOLVE(SteamAPI_Init,                              FnBoolVoid);
    RESOLVE(SteamAPI_InitSafe,                          FnBoolVoid);
    RESOLVE(SteamAPI_InitFlat,                          FnInitFlat);
    RESOLVE(SteamAPI_Shutdown,                          FnVoidVoid);
    RESOLVE(SteamAPI_RestartAppIfNecessary,             FnRestartApp);
    RESOLVE(SteamAPI_RunCallbacks,                      FnVoidVoid);
    RESOLVE(SteamAPI_IsSteamRunning,                    FnBoolVoid);
    RESOLVE(SteamInternal_CreateInterface,              FnCreateInterface);
    RESOLVE(SteamInternal_FindOrCreateUserInterface,    FnFindOrCreateUser);
    RESOLVE(SteamInternal_FindOrCreateGameServerInterface, FnFindOrCreateGS);
    RESOLVE(SteamInternal_ContextInit,                  FnContextInit);
    RESOLVE(SteamAPI_GetHSteamPipe,                     FnGetHandle);
    RESOLVE(SteamAPI_GetHSteamUser,                     FnGetHandle);
    RESOLVE(SteamAPI_RegisterCallback,                  FnRegisterCb);
    RESOLVE(SteamAPI_UnregisterCallback,                FnUnregisterCb);
    RESOLVE(SteamAPI_RegisterCallResult,                FnRegisterCr);
    RESOLVE(SteamAPI_UnregisterCallResult,              FnUnregisterCr);
}
#undef RESOLVE

#define REG_INTERCEPT(funcName) \
    g_InterceptedFunctions[#funcName] = reinterpret_cast<FARPROC>(&funcName)

static void BuildInterceptTable()
{
    REG_INTERCEPT(SteamAPI_Init);
    REG_INTERCEPT(SteamAPI_InitSafe);
    REG_INTERCEPT(SteamAPI_InitFlat);
    REG_INTERCEPT(SteamAPI_Shutdown);
    REG_INTERCEPT(SteamAPI_RestartAppIfNecessary);
    REG_INTERCEPT(SteamAPI_RunCallbacks);
    REG_INTERCEPT(SteamAPI_IsSteamRunning);
    REG_INTERCEPT(SteamInternal_CreateInterface);
    REG_INTERCEPT(SteamInternal_FindOrCreateUserInterface);
    REG_INTERCEPT(SteamInternal_FindOrCreateGameServerInterface);
    REG_INTERCEPT(SteamInternal_ContextInit);
    REG_INTERCEPT(SteamAPI_GetHSteamPipe);
    REG_INTERCEPT(SteamAPI_GetHSteamUser);
    REG_INTERCEPT(SteamAPI_RegisterCallback);
    REG_INTERCEPT(SteamAPI_UnregisterCallback);
    REG_INTERCEPT(SteamAPI_RegisterCallResult);
    REG_INTERCEPT(SteamAPI_UnregisterCallResult);
}
#undef REG_INTERCEPT

static bool AttachDetours()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG error = DetourAttach(&(PVOID&)Real_GetProcAddress, Hooked_GetProcAddress);
    if (error != NO_ERROR)
    {
        TraceLog("DetourAttach(GetProcAddress) failed: %ld", error);
        DetourTransactionAbort();
        return false;
    }
	
	IpcDump_AttachHooks();
	
    error = DetourTransactionCommit();
    if (error != NO_ERROR)
    {
        TraceLog("DetourTransactionCommit failed: %ld", error);
        return false;
    }
    TraceLog("Detours: GetProcAddress hooked for lazy-call interception");
    return true;
}

static void DetachDetours()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_GetProcAddress, Hooked_GetProcAddress);
	IpcDump_DetachHooks();
    DetourTransactionCommit();
}

// ============================================================================
// DLL Entry Point
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        InitLog();
        TraceLog("=== Proxy DLL Loaded (Detours + ASM Forwarding) ===");

        if (!LoadOriginalDll())
        {
            TraceLog("FATAL: Could not load steam_api64_o.dll!");
            DWORD err = GetLastError();
            char msg[512];
            snprintf(msg, sizeof(msg),
                "Failed to load steam_api64_o.dll\nError code: %lu\n\n"
                "Make sure the original DLL is renamed to steam_api64_o.dll",
                err);
            MessageBoxA(NULL, msg, "Steam API Proxy", MB_ICONERROR);
            CloseLog();
            return FALSE;
        }
        TraceLog("Original DLL loaded at: %p", g_OriginalDll);

        ResolveOriginalFunctions();
        ResolveDataExports();
        BuildInterceptTable();
		IpcDump_Init();

        if (!AttachDetours())
            TraceLog("WARNING: Detours attach failed");

        TraceLog("=== Proxy initialization complete ===");
        break;
    }

    case DLL_PROCESS_DETACH:
    {
        TraceLog("=== Proxy DLL Unloading ===");

        // Print context summary
        {
            std::lock_guard<std::mutex> lock(g_CtxMapMutex);
            TraceLog("Context map summary (%zu entries):", g_CtxDataToName.size());
            for (const auto& kv : g_CtxDataToName)
                TraceLog("  ctx 0x%llX -> %s",
                         (unsigned long long)kv.first, kv.second.c_str());
        }
        {
            std::lock_guard<std::mutex> lock(g_IfaceMapMutex);
            TraceLog("Interface map summary (%zu entries):", g_IfacePtrToName.size());
            for (const auto& kv : g_IfacePtrToName)
                TraceLog("  iface %p -> %s",
                         (void*)kv.first, kv.second.c_str());
        }

        TraceLog("RunCallbacks total: %ld", g_RunCallbacksCount);
        DetachDetours();
		
		IpcDump_Shutdown();

        if (g_OriginalDll && lpReserved == NULL)
            FreeLibrary(g_OriginalDll);
        g_OriginalDll = nullptr;

        TraceLog("=== Proxy DLL Unloaded ===");
        CloseLog();
        break;
    }
    }
    return TRUE;
}