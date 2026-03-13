// ============================================================================
//  IPC / Callback Payload Dump Module
//
//  Strategy: Hook Steam-internal callback dispatch to capture all callback
//  payloads, plus SteamAPI_ManualDispatch_* for newer SDK paths.
//
//  This module does NOT hook any global Win32 API (CreateFile, ReadFile, etc.)
//  so it cannot cause crashes in unrelated code paths.
//
//  Output:
//    - ipc_trace.log      (human-readable text with hex dumps)
//    - ipc_payloads.bin   (binary records for offline analysis)
//
//  Binary record format (little-endian):
//    [4B magic 0x53544D50]
//    [8B timestamp_us]
//    [4B thread_id]
//    [4B callback_id or method_hash]
//    [1B type: 'C'=callback, 'R'=callresult, 'M'=method]
//    [1B flags]
//    [2B reserved]
//    [4B payload_size]
//    [NB payload]
//    [4B crc32]
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <algorithm>

#include "ipc_dump.h"

// ============================================================================
// TraceLog from steam_api_proxy.cpp
// ============================================================================
extern void TraceLog(const char* fmt, ...);

// ============================================================================
// Original DLL handle from steam_api_proxy.cpp
// ============================================================================
extern "C" { extern HMODULE g_OriginalDll; }

// ============================================================================
// Configuration
// ============================================================================
static constexpr size_t   HEX_PREVIEW_BYTES = 128;
static constexpr size_t   MAX_CAPTURE_SIZE  = 1 * 1024 * 1024;
static constexpr uint32_t RECORD_MAGIC      = 0x53544D50;

// ============================================================================
// Log files
// ============================================================================
static FILE*         g_IpcTextLog   = nullptr;
static FILE*         g_IpcBinLog    = nullptr;
static std::mutex    g_IpcLogMutex;
static LARGE_INTEGER g_IpcStartTime = {};
static LARGE_INTEGER g_IpcFrequency = {};

// Statistics
static volatile long g_TotalCallbacks   = 0;
static volatile long g_TotalCallResults = 0;
static volatile long g_TotalDispatched  = 0;

// ============================================================================
// CRC32
// ============================================================================
static uint32_t g_Crc32Table[256];

static void InitCrc32()
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        g_Crc32Table[i] = c;
    }
}

static uint32_t CalcCrc32(const uint8_t* data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = g_Crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// Timestamp helpers
// ============================================================================
static double GetTimestampMs()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return static_cast<double>(now.QuadPart - g_IpcStartTime.QuadPart)
         * 1000.0 / static_cast<double>(g_IpcFrequency.QuadPart);
}

static uint64_t GetTimestampUs()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return static_cast<uint64_t>(
        (now.QuadPart - g_IpcStartTime.QuadPart) * 1000000ULL / g_IpcFrequency.QuadPart
    );
}

// ============================================================================
// Callback name lookup (extended)
// ============================================================================
static const char* GetCallbackNameEx(int id)
{
    switch (id)
    {
    // ISteamUser
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

    // ISteamFriends
    case 331:  return "FriendRichPresenceUpdate_t";
    case 332:  return "GameRichPresenceJoinRequested_t";
    case 333:  return "FavoritesListChanged_t";
    case 334:  return "FriendGameInfo_t";
    case 335:  return "ClanOfficerListResponse_t";
    case 336:  return "LobbyCreated_t";
    case 337:  return "LobbyEnter_t";
    case 338:  return "LobbyInvite_t";
    case 339:  return "FriendsGroupID_t";
    case 340:  return "FriendGameInfo_t(ext)";
    case 341:  return "FriendSessionStateInfo_t";
    case 342:  return "PersonaStateChange_t";
    case 343:  return "GameOverlayActivated_t";
    case 347:  return "FriendGameInfo_t(v2)";
    case 348:  return "AvatarImageLoaded_t";
    case 349:  return "ClanOfficerListResponse_t(v2)";

    // ISteamMatchmaking
    case 304:  return "LobbyDataUpdate_t";
    case 305:  return "LobbyChatUpdate_t";
    case 306:  return "LobbyChatMsg_t";
    case 309:  return "LobbyMatchList_t";
    case 512:  return "LobbyGameCreated_t";

    // ISteamNetworking
    case 504:  return "P2PSessionRequest_t";
    case 505:  return "P2PSessionConnectFail_t";
    case 506:  return "SocketStatusCallback_t";

    // ISteamScreenshots
    case 704:  return "ScreenshotReady_t";

    // ISteamUserStats
    case 1101: return "UserStatsReceived_t";
    case 1102: return "UserStatsStored_t";
    case 1103: return "UserAchievementStored_t";
    case 1108: return "UserStatsUnloaded_t";
    case 1109: return "UserAchievementIconFetched_t";

    // ISteamNetworkingMessages / Sockets
    case 1201: return "SteamNetworkingMessagesSessionRequest_t";
    case 1202: return "SteamNetConnectionStatusChangedCallback_t";
    case 1203: return "SteamNetAuthenticationStatus_t";
    case 1221: return "SteamRelayNetworkStatus_t";

    // ISteamRemoteStorage
    case 1307: return "RemoteStoragePublishFileProgress_t";
    case 1309: return "RemoteStoragePublishedFileUpdated_t";

    // ISteamInput
    case 2801: return "SteamInputDeviceConnected_t";
    case 2802: return "SteamInputDeviceDisconnected_t";
    case 2803: return "SteamInputConfigurationLoaded_t";
    case 2804: return "SteamInputGamepadSlotChange_t";

    // ISteamUGC
    case 3401: return "SteamUGCQueryCompleted_t";
    case 3402: return "SteamUGCRequestUGCDetailsResult_t";
    case 3403: return "CreateItemResult_t";
    case 3404: return "SubmitItemUpdateResult_t";
    case 3405: return "ItemInstalled_t";
    case 3406: return "DownloadItemResult_t";
    case 3407: return "UserFavoriteItemsListChanged_t";
    case 3412: return "WorkshopEULAStatus_t";

    // ISteamApps
    case 1005: return "DlcInstalled_t";
    case 1014: return "NewUrlLaunchParameters_t";
    case 1030: return "TimedTrialStatus_t";

    // ISteamUtils
    case 502:  return "IPCountry_t";
    case 503:  return "LowBatteryPower_t";
    case 701:  return "SteamAPICallCompleted_t";
    case 702:  return "CheckFileSignature_t";
    case 703:  return "GamepadTextInputDismissed_t";
    case 736:  return "AppResumingFromSuspend_t";
    case 738:  return "FloatingGamepadTextInputDismissed_t";
    case 739:  return "FilterTextDictionaryChanged_t";

    default:   return nullptr;
    }
}

// ============================================================================
// Hex dump formatter
// ============================================================================
static std::string FormatHexDump(const uint8_t* data, size_t len, size_t maxBytes)
{
    std::string result;
    size_t show = (std::min)(len, maxBytes);
    result.reserve(show * 4 + 256);

    char buf[16];
    for (size_t i = 0; i < show; i++)
    {
        if (i > 0 && (i % 16) == 0)
            result += "\n║                  ";
        else if (i > 0 && (i % 8) == 0)
            result += "  ";
        else if (i > 0)
            result += ' ';
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        result += buf;
    }

    if (len > show)
    {
        char extra[64];
        snprintf(extra, sizeof(extra), " ... (+%zu more)", len - show);
        result += extra;
    }

    // ASCII line
    result += "\n║           ASCII: ";
    for (size_t i = 0; i < show; i++)
    {
        if (i > 0 && (i % 64) == 0)
            result += "\n║                  ";
        result += (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
    }

    return result;
}

// ============================================================================
// Write binary record
// ============================================================================
static void WriteBinaryRecord(uint32_t callbackOrId, char type, uint8_t flags,
                               const uint8_t* data, uint32_t size)
{
    if (!g_IpcBinLog || !data || size == 0) return;

    std::lock_guard<std::mutex> lock(g_IpcLogMutex);
    if (!g_IpcBinLog) return;

    uint64_t ts = GetTimestampUs();
    uint32_t tid = GetCurrentThreadId();
    uint16_t reserved = 0;
    uint32_t crc = CalcCrc32(data, size);

    fwrite(&RECORD_MAGIC,    4, 1, g_IpcBinLog);
    fwrite(&ts,              8, 1, g_IpcBinLog);
    fwrite(&tid,             4, 1, g_IpcBinLog);
    fwrite(&callbackOrId,    4, 1, g_IpcBinLog);
    fwrite(&type,            1, 1, g_IpcBinLog);
    fwrite(&flags,           1, 1, g_IpcBinLog);
    fwrite(&reserved,        2, 1, g_IpcBinLog);
    fwrite(&size,            4, 1, g_IpcBinLog);
    fwrite(data,             1, size, g_IpcBinLog);
    fwrite(&crc,             4, 1, g_IpcBinLog);
    fflush(g_IpcBinLog);
}

// ============================================================================
// Write text log entry
// ============================================================================
static void WriteTextLog(const char* source, int callbackId, char type,
                          const uint8_t* data, uint32_t size,
                          const char* extraInfo = nullptr)
{
    if (!g_IpcTextLog) return;

    std::lock_guard<std::mutex> lock(g_IpcLogMutex);
    if (!g_IpcTextLog) return;

    double ms = GetTimestampMs();
    const char* cbName = GetCallbackNameEx(callbackId);

    fprintf(g_IpcTextLog,
        "╔══════════════════════════════════════════════════════════════\n"
        "║ [%12.3f ms] TID:%05lu  %s\n"
        "║ Callback ID: %d%s%s\n"
        "║ Type: %c (%s)  Payload: %u bytes (0x%X)\n",
        ms, GetCurrentThreadId(), source,
        callbackId,
        cbName ? "  (" : "",
        cbName ? cbName : "",
        type,
        type == 'C' ? "CALLBACK" : (type == 'R' ? "CALLRESULT" : "DISPATCH"),
        size, size);

    if (cbName)
        fprintf(g_IpcTextLog, "║ Name: %s)\n", cbName);

    if (extraInfo)
        fprintf(g_IpcTextLog, "║ Info: %s\n", extraInfo);

    if (data && size > 0)
    {
        std::string hex = FormatHexDump(data, size, HEX_PREVIEW_BYTES);
        fprintf(g_IpcTextLog, "║ Hex:  %s\n", hex.c_str());
    }

    fprintf(g_IpcTextLog,
        "╚══════════════════════════════════════════════════════════════\n\n");
    fflush(g_IpcTextLog);
}

// ============================================================================
// Steam callback structures (from Steamworks SDK)
// ============================================================================

// CCallbackBase layout (x64):
//   vtable ptr     [8 bytes]  offset 0
//   m_nCallbackFlags [1 byte] offset 8  (0x01 = registered, 0x02 = game server)
//   m_iCallback     [4 bytes] offset 12
//
// Note: There's padding, so m_iCallback is at offset 12 on most compilers.

#pragma pack(push, 8)
struct CallbackMsg_t
{
    int32_t  m_hSteamUser;      // +0
    int32_t  m_iCallback;       // +4
    uint8_t* m_pubParam;        // +8
    int32_t  m_cubParam;        // +16
};
#pragma pack(pop)

// ============================================================================
// Function typedefs for Steam internal dispatch functions
// ============================================================================

// SteamAPI_ManualDispatch_Init(void)
typedef void  (*FnManualDispatchInit)();

// SteamAPI_ManualDispatch_RunFrame(HSteamPipe)
typedef void  (*FnManualDispatchRunFrame)(int32_t);

// SteamAPI_ManualDispatch_GetNextCallback(HSteamPipe, CallbackMsg_t*) -> bool
typedef bool  (*FnManualDispatchGetNext)(int32_t, CallbackMsg_t*);

// SteamAPI_ManualDispatch_FreeLastCallback(HSteamPipe)
typedef void  (*FnManualDispatchFreeLastCb)(int32_t);

// SteamAPI_ManualDispatch_GetAPICallResult(HSteamPipe, SteamAPICall_t,
//     void*, int, int, bool*) -> bool
typedef bool  (*FnManualDispatchGetResult)(int32_t, uint64_t, void*, int, int, bool*);

// steam_api_internal: SteamAPI_RunCallbacks dispatches via an internal function
// We also hook the callback registration to read payload on dispatch.

// Original function pointers
static FnManualDispatchInit       Real_ManualDispatch_Init      = nullptr;
static FnManualDispatchRunFrame   Real_ManualDispatch_RunFrame  = nullptr;
static FnManualDispatchGetNext    Real_ManualDispatch_GetNext   = nullptr;
static FnManualDispatchFreeLastCb Real_ManualDispatch_FreeLast  = nullptr;
static FnManualDispatchGetResult  Real_ManualDispatch_GetResult = nullptr;

// ============================================================================
// Hooked: SteamAPI_ManualDispatch_GetNextCallback
// This is the primary interception point for callback payloads
// ============================================================================
static bool Hooked_ManualDispatch_GetNext(int32_t hSteamPipe, CallbackMsg_t* pCallbackMsg)
{
    bool result = Real_ManualDispatch_GetNext(hSteamPipe, pCallbackMsg);

    if (result && pCallbackMsg && pCallbackMsg->m_pubParam && pCallbackMsg->m_cubParam > 0)
    {
        int cbId = pCallbackMsg->m_iCallback;
        uint32_t size = (uint32_t)pCallbackMsg->m_cubParam;

        if (size <= MAX_CAPTURE_SIZE)
        {
            InterlockedIncrement(&g_TotalDispatched);
            WriteTextLog("ManualDispatch_GetNextCallback",
                          cbId, 'D', pCallbackMsg->m_pubParam, size);
            WriteBinaryRecord((uint32_t)cbId, 'D', 0x00,
                               pCallbackMsg->m_pubParam, size);
        }
    }
    return result;
}

// ============================================================================
// Hooked: SteamAPI_ManualDispatch_GetAPICallResult
// Captures async call results (CCallResult payloads)
// ============================================================================
static bool Hooked_ManualDispatch_GetResult(
    int32_t hSteamPipe, uint64_t hSteamAPICall,
    void* pCallback, int cubCallback,
    int iCallbackExpected, bool* pbFailed)
{
    bool result = Real_ManualDispatch_GetResult(
        hSteamPipe, hSteamAPICall, pCallback, cubCallback, iCallbackExpected, pbFailed);

    if (result && pCallback && cubCallback > 0)
    {
        uint32_t size = (uint32_t)cubCallback;
        bool failed = pbFailed ? *pbFailed : false;

        if (size <= MAX_CAPTURE_SIZE)
        {
            InterlockedIncrement(&g_TotalCallResults);

            char info[128];
            snprintf(info, sizeof(info), "APICall=0x%llX, expected=%d, failed=%s",
                     (unsigned long long)hSteamAPICall, iCallbackExpected,
                     failed ? "true" : "false");

            WriteTextLog("ManualDispatch_GetAPICallResult",
                          iCallbackExpected, 'R',
                          static_cast<const uint8_t*>(pCallback), size, info);
            WriteBinaryRecord((uint32_t)iCallbackExpected, 'R',
                               failed ? 0x80 : 0x00,
                               static_cast<const uint8_t*>(pCallback), size);
        }
    }
    return result;
}

// ============================================================================
// Hooked: SteamAPI_ManualDispatch_RunFrame (just log)
// ============================================================================
static void Hooked_ManualDispatch_RunFrame(int32_t hSteamPipe)
{
    Real_ManualDispatch_RunFrame(hSteamPipe);
    // Very high frequency - only log occasionally
    static volatile long count = 0;
    long c = InterlockedIncrement(&count);
    if (c == 1 || c % 5000 == 0)
        TraceLog("[IPC] ManualDispatch_RunFrame pipe=%d (call #%ld)", hSteamPipe, c);
}

// ============================================================================
// SteamAPI_RegisterCallback / RunCallbacks payload capture
//
// For games using the traditional (non-ManualDispatch) API, callbacks are
// dispatched internally during SteamAPI_RunCallbacks(). The callback object's
// Run() virtual method is called with the payload.
//
// We intercept this by hooking the INTERNAL dispatch function that
// steamclient64.dll uses: Steam_BGetCallback / Steam_FreeLastCallback.
// These are older internal functions that RunCallbacks uses under the hood.
// ============================================================================

// Steam_BGetCallback(HSteamPipe, CallbackMsg_t*) -> bool
typedef bool (*FnSteamBGetCallback)(int32_t, CallbackMsg_t*);
// Steam_FreeLastCallback(HSteamPipe)
typedef void (*FnSteamFreeLastCallback)(int32_t);
// Steam_GetAPICallResult(HSteamPipe, SteamAPICall_t, void*, int, int, bool*) -> bool
typedef bool (*FnSteamGetAPICallResult)(int32_t, uint64_t, void*, int, int, bool*);

static FnSteamBGetCallback      Real_Steam_BGetCallback      = nullptr;
static FnSteamFreeLastCallback  Real_Steam_FreeLastCallback   = nullptr;
static FnSteamGetAPICallResult  Real_Steam_GetAPICallResult   = nullptr;

static bool Hooked_Steam_BGetCallback(int32_t hSteamPipe, CallbackMsg_t* pCallbackMsg)
{
    bool result = Real_Steam_BGetCallback(hSteamPipe, pCallbackMsg);

    if (result && pCallbackMsg && pCallbackMsg->m_pubParam && pCallbackMsg->m_cubParam > 0)
    {
        int cbId = pCallbackMsg->m_iCallback;
        uint32_t size = (uint32_t)pCallbackMsg->m_cubParam;

        if (size <= MAX_CAPTURE_SIZE)
        {
            InterlockedIncrement(&g_TotalCallbacks);
            WriteTextLog("Steam_BGetCallback",
                          cbId, 'C', pCallbackMsg->m_pubParam, size);
            WriteBinaryRecord((uint32_t)cbId, 'C', 0x00,
                               pCallbackMsg->m_pubParam, size);
        }
    }
    return result;
}

static void Hooked_Steam_FreeLastCallback(int32_t hSteamPipe)
{
    Real_Steam_FreeLastCallback(hSteamPipe);
}

static bool Hooked_Steam_GetAPICallResult(
    int32_t hSteamPipe, uint64_t hSteamAPICall,
    void* pCallback, int cubCallback,
    int iCallbackExpected, bool* pbFailed)
{
    bool result = Real_Steam_GetAPICallResult(
        hSteamPipe, hSteamAPICall, pCallback, cubCallback, iCallbackExpected, pbFailed);

    if (result && pCallback && cubCallback > 0)
    {
        uint32_t size = (uint32_t)cubCallback;
        bool failed = pbFailed ? *pbFailed : false;

        if (size <= MAX_CAPTURE_SIZE)
        {
            InterlockedIncrement(&g_TotalCallResults);

            char info[128];
            snprintf(info, sizeof(info), "APICall=0x%llX, expected=%d, failed=%s",
                     (unsigned long long)hSteamAPICall, iCallbackExpected,
                     failed ? "true" : "false");

            WriteTextLog("Steam_GetAPICallResult",
                          iCallbackExpected, 'R',
                          static_cast<const uint8_t*>(pCallback), size, info);
            WriteBinaryRecord((uint32_t)iCallbackExpected, 'R',
                               failed ? 0x80 : 0x00,
                               static_cast<const uint8_t*>(pCallback), size);
        }
    }
    return result;
}

// ============================================================================
// Resolve and attach hooks
// ============================================================================

// Track which hooks are active (some functions may not exist in all SDK versions)
static bool g_HaveManualDispatch = false;
static bool g_HaveSteamInternal  = false;

static void ResolveIpcFunctions()
{
    if (!g_OriginalDll) return;

    // Try ManualDispatch (newer SDK)
    Real_ManualDispatch_Init = reinterpret_cast<FnManualDispatchInit>(
        GetProcAddress(g_OriginalDll, "SteamAPI_ManualDispatch_Init"));
    Real_ManualDispatch_RunFrame = reinterpret_cast<FnManualDispatchRunFrame>(
        GetProcAddress(g_OriginalDll, "SteamAPI_ManualDispatch_RunFrame"));
    Real_ManualDispatch_GetNext = reinterpret_cast<FnManualDispatchGetNext>(
        GetProcAddress(g_OriginalDll, "SteamAPI_ManualDispatch_GetNextCallback"));
    Real_ManualDispatch_FreeLast = reinterpret_cast<FnManualDispatchFreeLastCb>(
        GetProcAddress(g_OriginalDll, "SteamAPI_ManualDispatch_FreeLastCallback"));
    Real_ManualDispatch_GetResult = reinterpret_cast<FnManualDispatchGetResult>(
        GetProcAddress(g_OriginalDll, "SteamAPI_ManualDispatch_GetAPICallResult"));

    g_HaveManualDispatch = (Real_ManualDispatch_GetNext != nullptr);

    TraceLog("[IPC] ManualDispatch functions: %s",
             g_HaveManualDispatch ? "FOUND" : "not found");

    // Try Steam_BGetCallback (older internal path, exported from steamclient64.dll)
    // First try from our steam_api64_o.dll (it might re-export them)
    Real_Steam_BGetCallback = reinterpret_cast<FnSteamBGetCallback>(
        GetProcAddress(g_OriginalDll, "Steam_BGetCallback"));
    Real_Steam_FreeLastCallback = reinterpret_cast<FnSteamFreeLastCallback>(
        GetProcAddress(g_OriginalDll, "Steam_FreeLastCallback"));
    Real_Steam_GetAPICallResult = reinterpret_cast<FnSteamGetAPICallResult>(
        GetProcAddress(g_OriginalDll, "Steam_GetAPICallResult"));

    // If not in steam_api64, try steamclient64.dll directly
    if (!Real_Steam_BGetCallback)
    {
        HMODULE hClient = GetModuleHandleA("steamclient64.dll");
        if (!hClient)
            hClient = LoadLibraryA("steamclient64.dll");

        if (hClient)
        {
            Real_Steam_BGetCallback = reinterpret_cast<FnSteamBGetCallback>(
                GetProcAddress(hClient, "Steam_BGetCallback"));
            Real_Steam_FreeLastCallback = reinterpret_cast<FnSteamFreeLastCallback>(
                GetProcAddress(hClient, "Steam_FreeLastCallback"));
            Real_Steam_GetAPICallResult = reinterpret_cast<FnSteamGetAPICallResult>(
                GetProcAddress(hClient, "Steam_GetAPICallResult"));
            TraceLog("[IPC] Resolved Steam_BGetCallback from steamclient64.dll");
        }
    }

    g_HaveSteamInternal = (Real_Steam_BGetCallback != nullptr);

    TraceLog("[IPC] Steam_BGetCallback: %s",
             g_HaveSteamInternal ? "FOUND" : "not found");
}

void IpcDump_AttachHooks()
{
    // ManualDispatch hooks
    if (Real_ManualDispatch_GetNext)
    {
        DetourAttach(&(PVOID&)Real_ManualDispatch_GetNext, Hooked_ManualDispatch_GetNext);
        TraceLog("[IPC] Attached: ManualDispatch_GetNextCallback");
    }
    if (Real_ManualDispatch_GetResult)
    {
        DetourAttach(&(PVOID&)Real_ManualDispatch_GetResult, Hooked_ManualDispatch_GetResult);
        TraceLog("[IPC] Attached: ManualDispatch_GetAPICallResult");
    }
    if (Real_ManualDispatch_RunFrame)
    {
        DetourAttach(&(PVOID&)Real_ManualDispatch_RunFrame, Hooked_ManualDispatch_RunFrame);
        TraceLog("[IPC] Attached: ManualDispatch_RunFrame");
    }

    // Steam_BGetCallback hooks
    if (Real_Steam_BGetCallback)
    {
        DetourAttach(&(PVOID&)Real_Steam_BGetCallback, Hooked_Steam_BGetCallback);
        TraceLog("[IPC] Attached: Steam_BGetCallback");
    }
    if (Real_Steam_FreeLastCallback)
    {
        DetourAttach(&(PVOID&)Real_Steam_FreeLastCallback, Hooked_Steam_FreeLastCallback);
        TraceLog("[IPC] Attached: Steam_FreeLastCallback");
    }
    if (Real_Steam_GetAPICallResult)
    {
        DetourAttach(&(PVOID&)Real_Steam_GetAPICallResult, Hooked_Steam_GetAPICallResult);
        TraceLog("[IPC] Attached: Steam_GetAPICallResult");
    }
}

void IpcDump_DetachHooks()
{
    if (Real_ManualDispatch_GetNext)
        DetourDetach(&(PVOID&)Real_ManualDispatch_GetNext, Hooked_ManualDispatch_GetNext);
    if (Real_ManualDispatch_GetResult)
        DetourDetach(&(PVOID&)Real_ManualDispatch_GetResult, Hooked_ManualDispatch_GetResult);
    if (Real_ManualDispatch_RunFrame)
        DetourDetach(&(PVOID&)Real_ManualDispatch_RunFrame, Hooked_ManualDispatch_RunFrame);
    if (Real_Steam_BGetCallback)
        DetourDetach(&(PVOID&)Real_Steam_BGetCallback, Hooked_Steam_BGetCallback);
    if (Real_Steam_FreeLastCallback)
        DetourDetach(&(PVOID&)Real_Steam_FreeLastCallback, Hooked_Steam_FreeLastCallback);
    if (Real_Steam_GetAPICallResult)
        DetourDetach(&(PVOID&)Real_Steam_GetAPICallResult, Hooked_Steam_GetAPICallResult);
}

// ============================================================================
// Public API
// ============================================================================

void IpcDump_Init()
{
    QueryPerformanceFrequency(&g_IpcFrequency);
    QueryPerformanceCounter(&g_IpcStartTime);
    InitCrc32();

#ifdef _MSC_VER
    errno_t err;
    err = fopen_s(&g_IpcTextLog, "ipc_trace.log", "w");
    if (err != 0) g_IpcTextLog = nullptr;
    err = fopen_s(&g_IpcBinLog, "ipc_payloads.bin", "wb");
    if (err != 0) g_IpcBinLog = nullptr;
#else
    g_IpcTextLog = fopen("ipc_trace.log", "w");
    g_IpcBinLog  = fopen("ipc_payloads.bin", "wb");
#endif

    if (g_IpcTextLog)
    {
        fprintf(g_IpcTextLog,
            "╔══════════════════════════════════════════════════════════════\n"
            "║  Steam Callback/IPC Payload Trace Log\n"
            "║  Generated by Steam API Proxy (Detours Edition)\n"
            "║  Binary companion: ipc_payloads.bin\n"
            "║\n"
            "║  Record types:\n"
            "║    C = Callback (from Steam_BGetCallback / RunCallbacks)\n"
            "║    R = CallResult (async API call result)\n"
            "║    D = Dispatch  (ManualDispatch path)\n"
            "╚══════════════════════════════════════════════════════════════\n\n");
        fflush(g_IpcTextLog);
    }

    if (g_IpcBinLog)
    {
        const char magic[] = "STMP_IPC_DUMP_V2";
        fwrite(magic, 1, 16, g_IpcBinLog);
        fflush(g_IpcBinLog);
    }

    // Resolve Steam-internal dispatch functions
    ResolveIpcFunctions();

    TraceLog("[IPC] Dump module initialized (text=%s, bin=%s)",
             g_IpcTextLog ? "OK" : "FAIL",
             g_IpcBinLog ? "OK" : "FAIL");
}

void IpcDump_Shutdown()
{
    TraceLog("[IPC] Shutdown: callbacks=%ld, callresults=%ld, dispatched=%ld",
             g_TotalCallbacks, g_TotalCallResults, g_TotalDispatched);

    std::lock_guard<std::mutex> lock(g_IpcLogMutex);

    if (g_IpcTextLog)
    {
        fprintf(g_IpcTextLog,
            "\n╔══════════════════════════════════════════════════════════════\n"
            "║  Session Summary\n"
            "║  Callbacks captured:    %ld\n"
            "║  CallResults captured:  %ld\n"
            "║  ManualDispatched:      %ld\n"
            "║  ManualDispatch hooks:  %s\n"
            "║  Steam_BGetCallback:    %s\n"
            "╚══════════════════════════════════════════════════════════════\n",
            g_TotalCallbacks, g_TotalCallResults, g_TotalDispatched,
            g_HaveManualDispatch ? "active" : "not available",
            g_HaveSteamInternal ? "active" : "not available");
        fflush(g_IpcTextLog);
        fclose(g_IpcTextLog);
        g_IpcTextLog = nullptr;
    }

    if (g_IpcBinLog)
    {
        fflush(g_IpcBinLog);
        fclose(g_IpcBinLog);
        g_IpcBinLog = nullptr;
    }
}