// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
// Host nativo mínimo para tunnel.dll. Se compila en GitHub Actions y luego
// queda embebido dentro de Conectar-Gateway.exe junto con los DLL oficiales.
//
// La telemetría se lee aquí, dentro del servicio elevado, porque WireGuardNT
// puede denegar WireGuardOpenAdapter al proceso Wails no elevado. El archivo
// .stats.bin contiene únicamente public keys y contadores; nunca PrivateKey ni
// PresharedKey.
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <string.h>

#define WG_PATH_CAP 32768
#define WG_KEY_LENGTH 32
#define WG_ADAPTER_NAME_CAP 256
#define WG_STATS_VERSION 1
#define WG_STATS_INTERVAL_MS 1000
#define WG_STATS_INITIAL_BYTES (64 * 1024)
#define WG_STATS_MAX_BYTES (16 * 1024 * 1024)

#ifndef ERROR_MORE_DATA
#define ERROR_MORE_DATA 234L
#endif

typedef BOOL (__cdecl *WireGuardTunnelServiceFn)(LPCWSTR configFile);
typedef void *WG_ADAPTER_HANDLE;
typedef WG_ADAPTER_HANDLE (WINAPI *WGOpenAdapterFn)(LPCWSTR Name);
typedef VOID (WINAPI *WGCloseAdapterFn)(WG_ADAPTER_HANDLE Adapter);
typedef BOOL (WINAPI *WGGetConfigurationFn)(WG_ADAPTER_HANDLE Adapter, void *Config, DWORD *Bytes);

typedef struct __declspec(align(8)) WG_INTERFACE {
    DWORD Flags;
    WORD ListenPort;
    BYTE PrivateKey[WG_KEY_LENGTH];
    BYTE PublicKey[WG_KEY_LENGTH];
    DWORD PeersCount;
} WG_INTERFACE;

typedef struct __declspec(align(8)) WG_PEER {
    DWORD Flags;
    DWORD Reserved;
    BYTE PublicKey[WG_KEY_LENGTH];
    BYTE PresharedKey[WG_KEY_LENGTH];
    WORD PersistentKeepalive;
    SOCKADDR_INET Endpoint;
    uint64_t TxBytes;
    uint64_t RxBytes;
    uint64_t LastHandshake;
    DWORD AllowedIPsCount;
} WG_PEER;

typedef struct __declspec(align(8)) WG_ALLOWED_IP {
    union {
        IN_ADDR V4;
        IN6_ADDR V6;
    } Address;
    ADDRESS_FAMILY AddressFamily;
    BYTE Cidr;
    DWORD Flags;
} WG_ALLOWED_IP;

/* Fallar el build si el SDK cambia el ABI que usa WireGuardNT. */
typedef char wg_check_interface_size[(sizeof(WG_INTERFACE) == 80) ? 1 : -1];
typedef char wg_check_peer_size[(sizeof(WG_PEER) == 136) ? 1 : -1];
typedef char wg_check_allowed_ip_size[(sizeof(WG_ALLOWED_IP) == 24) ? 1 : -1];

#pragma pack(push, 1)
typedef struct WG_STATS_HEADER {
    char Magic[8];                 /* GWAWGST1 */
    DWORD Version;
    WORD ListenPort;
    WORD Reserved;
    DWORD PeersCount;
} WG_STATS_HEADER;

typedef struct WG_STATS_PEER {
    BYTE PublicKey[WG_KEY_LENGTH];
    uint64_t TxBytes;
    uint64_t RxBytes;
    uint64_t LastHandshake;
} WG_STATS_PEER;
#pragma pack(pop)

typedef struct WG_STATS_CONTEXT {
    HANDLE StopEvent;
    wchar_t ConfigPath[WG_PATH_CAP];
    wchar_t AdapterName[WG_ADAPTER_NAME_CAP];
    wchar_t WireGuardDLL[WG_PATH_CAP];
} WG_STATS_CONTEXT;

static BOOL wgAppendSuffix(LPCWSTR base, LPCWSTR suffix, wchar_t out[WG_PATH_CAP])
{
    size_t baseLen = base ? wcslen(base) : 0;
    size_t suffixLen = suffix ? wcslen(suffix) : 0;
    if (!base || !suffix || baseLen + suffixLen + 1 >= WG_PATH_CAP) {
        if (out)
            out[0] = L'\0';
        return FALSE;
    }
    wcscpy_s(out, WG_PATH_CAP, base);
    wcscat_s(out, WG_PATH_CAP, suffix);
    return TRUE;
}

static void wgLogPath(LPCWSTR configPath, wchar_t out[WG_PATH_CAP])
{
    if (!wgAppendSuffix(configPath, L".service-host.log", out))
        out[0] = L'\0';
}

static void wgStatsPath(LPCWSTR configPath, wchar_t out[WG_PATH_CAP])
{
    if (!wgAppendSuffix(configPath, L".stats.bin", out))
        out[0] = L'\0';
}

static void wgWriteError(LPCWSTR configPath, LPCWSTR stage, DWORD error)
{
    wchar_t logPath[WG_PATH_CAP];
    wgLogPath(configPath, logPath);
    if (!logPath[0])
        return;

    wchar_t systemMessage[1024] = L"";
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   systemMessage, (DWORD)(sizeof(systemMessage) / sizeof(systemMessage[0])), NULL);

    FILE *f = NULL;
    if (_wfopen_s(&f, logPath, L"w, ccs=UTF-8") != 0 || !f)
        return;
    fwprintf(f, L"stage=%ls\nerror=%lu\nmessage=%ls\n", stage, (unsigned long)error, systemMessage);
    fclose(f);
}

static void wgClearError(LPCWSTR configPath)
{
    wchar_t logPath[WG_PATH_CAP];
    wgLogPath(configPath, logPath);
    if (logPath[0])
        DeleteFileW(logPath);
}

static void wgDeleteStats(LPCWSTR configPath)
{
    wchar_t statsPath[WG_PATH_CAP];
    wgStatsPath(configPath, statsPath);
    if (statsPath[0])
        DeleteFileW(statsPath);
}

static BOOL wgAdapterNameFromConfig(LPCWSTR configPath, wchar_t out[WG_ADAPTER_NAME_CAP])
{
    LPCWSTR fileName;
    const wchar_t *slash1;
    const wchar_t *slash2;
    size_t len;

    if (!configPath || !out)
        return FALSE;
    slash1 = wcsrchr(configPath, L'\\');
    slash2 = wcsrchr(configPath, L'/');
    fileName = configPath;
    if (slash1 && slash1 + 1 > fileName)
        fileName = slash1 + 1;
    if (slash2 && slash2 + 1 > fileName)
        fileName = slash2 + 1;

    len = wcslen(fileName);
    if (len > 5 && _wcsicmp(fileName + len - 5, L".conf") == 0)
        len -= 5;
    if (!len || len >= WG_ADAPTER_NAME_CAP)
        return FALSE;

    wmemcpy(out, fileName, len);
    out[len] = L'\0';
    return TRUE;
}

static BOOL wgWriteStatsFile(LPCWSTR configPath, const WG_INTERFACE *iface, DWORD configBytes)
{
    const BYTE *base;
    size_t offset;
    size_t outputBytes;
    BYTE *output;
    WG_STATS_HEADER *header;
    WG_STATS_PEER *records;
    DWORD i;
    wchar_t path[WG_PATH_CAP];
    wchar_t tmpPath[WG_PATH_CAP];
    HANDLE file;
    DWORD written;
    BOOL ok;

    if (!configPath || !iface || configBytes < sizeof(WG_INTERFACE))
        return FALSE;

    if (iface->PeersCount > 65535)
        return FALSE;
    if ((size_t)iface->PeersCount > (SIZE_MAX - sizeof(WG_STATS_HEADER)) / sizeof(WG_STATS_PEER))
        return FALSE;

    outputBytes = sizeof(WG_STATS_HEADER) + (size_t)iface->PeersCount * sizeof(WG_STATS_PEER);
    output = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outputBytes);
    if (!output)
        return FALSE;

    header = (WG_STATS_HEADER *)output;
    memcpy(header->Magic, "GWAWGST1", 8);
    header->Version = WG_STATS_VERSION;
    header->ListenPort = iface->ListenPort;
    header->PeersCount = iface->PeersCount;
    records = (WG_STATS_PEER *)(output + sizeof(WG_STATS_HEADER));

    base = (const BYTE *)iface;
    offset = sizeof(WG_INTERFACE);
    for (i = 0; i < iface->PeersCount; ++i) {
        const WG_PEER *peer;
        size_t allowedBytes;
        if (offset > configBytes || sizeof(WG_PEER) > (size_t)configBytes - offset) {
            HeapFree(GetProcessHeap(), 0, output);
            return FALSE;
        }
        peer = (const WG_PEER *)(base + offset);
        memcpy(records[i].PublicKey, peer->PublicKey, WG_KEY_LENGTH);
        records[i].TxBytes = peer->TxBytes;
        records[i].RxBytes = peer->RxBytes;
        records[i].LastHandshake = peer->LastHandshake;
        offset += sizeof(WG_PEER);

        if ((size_t)peer->AllowedIPsCount > SIZE_MAX / sizeof(WG_ALLOWED_IP)) {
            HeapFree(GetProcessHeap(), 0, output);
            return FALSE;
        }
        allowedBytes = (size_t)peer->AllowedIPsCount * sizeof(WG_ALLOWED_IP);
        if (offset > configBytes || allowedBytes > (size_t)configBytes - offset) {
            HeapFree(GetProcessHeap(), 0, output);
            return FALSE;
        }
        offset += allowedBytes;
    }

    wgStatsPath(configPath, path);
    if (!path[0] || !wgAppendSuffix(path, L".tmp", tmpPath)) {
        HeapFree(GetProcessHeap(), 0, output);
        return FALSE;
    }

    file = CreateFileW(tmpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, output);
        return FALSE;
    }
    written = 0;
    ok = WriteFile(file, output, (DWORD)outputBytes, &written, NULL) && written == (DWORD)outputBytes;
    if (ok)
        ok = FlushFileBuffers(file);
    CloseHandle(file);
    HeapFree(GetProcessHeap(), 0, output);

    if (!ok) {
        DeleteFileW(tmpPath);
        return FALSE;
    }
    if (!MoveFileExW(tmpPath, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmpPath);
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI wgStatsThread(LPVOID param)
{
    WG_STATS_CONTEXT *ctx = (WG_STATS_CONTEXT *)param;
    HMODULE dll;
    WGOpenAdapterFn openAdapter;
    WGCloseAdapterFn closeAdapter;
    WGGetConfigurationFn getConfig;

    dll = LoadLibraryExW(ctx->WireGuardDLL, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!dll)
        return 1;

    openAdapter = (WGOpenAdapterFn)(void *)GetProcAddress(dll, "WireGuardOpenAdapter");
    closeAdapter = (WGCloseAdapterFn)(void *)GetProcAddress(dll, "WireGuardCloseAdapter");
    getConfig = (WGGetConfigurationFn)(void *)GetProcAddress(dll, "WireGuardGetConfiguration");
    if (!openAdapter || !closeAdapter || !getConfig) {
        FreeLibrary(dll);
        return 2;
    }

    while (WaitForSingleObject(ctx->StopEvent, 0) == WAIT_TIMEOUT) {
        WG_ADAPTER_HANDLE adapter = openAdapter(ctx->AdapterName);
        if (adapter) {
            DWORD capacity = WG_STATS_INITIAL_BYTES;
            BYTE *buffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, capacity);
            int attempt;
            if (buffer) {
                for (attempt = 0; attempt < 5; ++attempt) {
                    DWORD needed = capacity;
                    if (getConfig(adapter, buffer, &needed)) {
                        wgWriteStatsFile(ctx->ConfigPath, (const WG_INTERFACE *)buffer, needed);
                        break;
                    }
                    if (GetLastError() != ERROR_MORE_DATA || needed <= capacity || needed > WG_STATS_MAX_BYTES)
                        break;
                    {
                        BYTE *larger = (BYTE *)HeapReAlloc(GetProcessHeap(), 0, buffer, needed);
                        if (!larger)
                            break;
                        buffer = larger;
                        capacity = needed;
                    }
                }
                HeapFree(GetProcessHeap(), 0, buffer);
            }
            closeAdapter(adapter);
        }
        if (WaitForSingleObject(ctx->StopEvent, WG_STATS_INTERVAL_MS) != WAIT_TIMEOUT)
            break;
    }

    FreeLibrary(dll);
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    LPCWSTR configPath;
    wchar_t exePath[WG_PATH_CAP];
    wchar_t engineDir[WG_PATH_CAP];
    wchar_t tunnelPath[WG_PATH_CAP];
    wchar_t wireguardPath[WG_PATH_CAP];
    wchar_t *slash;
    DWORD n;
    HMODULE tunnel;
    WireGuardTunnelServiceFn tunnelService;
    WG_STATS_CONTEXT statsCtx;
    HANDLE statsThread = NULL;
    BOOL ok;
    DWORD err;

    if (argc != 3 || _wcsicmp(argv[1], L"/service") != 0)
        return 2;

    configPath = argv[2];
    n = GetModuleFileNameW(NULL, exePath, WG_PATH_CAP);
    if (!n || n >= WG_PATH_CAP) {
        err = GetLastError();
        wgWriteError(configPath, L"GetModuleFileNameW", err ? err : ERROR_INSUFFICIENT_BUFFER);
        return 3;
    }

    wcscpy_s(engineDir, WG_PATH_CAP, exePath);
    slash = wcsrchr(engineDir, L'\\');
    if (!slash) {
        wgWriteError(configPath, L"resolver directorio del host", ERROR_BAD_PATHNAME);
        return 3;
    }
    *slash = L'\0';

    if (!wgAppendSuffix(engineDir, L"\\tunnel.dll", tunnelPath) ||
        !wgAppendSuffix(engineDir, L"\\wireguard.dll", wireguardPath)) {
        wgWriteError(configPath, L"ruta de DLL WireGuard", ERROR_BUFFER_OVERFLOW);
        return 3;
    }

    // LOAD_WITH_ALTERED_SEARCH_PATH hace que las dependencias de tunnel.dll,
    // incluido wireguard.dll, se busquen también en este mismo directorio.
    tunnel = LoadLibraryExW(tunnelPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!tunnel) {
        err = GetLastError();
        wgWriteError(configPath, L"LoadLibraryExW(tunnel.dll)", err);
        return 4;
    }

    tunnelService = (WireGuardTunnelServiceFn)(void *)GetProcAddress(tunnel, "WireGuardTunnelService");
    if (!tunnelService) {
        err = GetLastError();
        wgWriteError(configPath, L"GetProcAddress(WireGuardTunnelService)", err);
        FreeLibrary(tunnel);
        return 5;
    }

    ZeroMemory(&statsCtx, sizeof(statsCtx));
    statsCtx.StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (statsCtx.StopEvent &&
        wgAdapterNameFromConfig(configPath, statsCtx.AdapterName)) {
        wcscpy_s(statsCtx.ConfigPath, WG_PATH_CAP, configPath);
        wcscpy_s(statsCtx.WireGuardDLL, WG_PATH_CAP, wireguardPath);
        wgDeleteStats(configPath);
        statsThread = CreateThread(NULL, 0, wgStatsThread, &statsCtx, 0, NULL);
    }

    wgClearError(configPath);
    SetLastError(ERROR_SUCCESS);
    ok = tunnelService(configPath);
    err = GetLastError();

    if (statsCtx.StopEvent) {
        SetEvent(statsCtx.StopEvent);
        if (statsThread) {
            WaitForSingleObject(statsThread, 3000);
            CloseHandle(statsThread);
        }
        CloseHandle(statsCtx.StopEvent);
    }
    wgDeleteStats(configPath);
    FreeLibrary(tunnel);

    if (!ok) {
        wgWriteError(configPath, L"WireGuardTunnelService", err ? err : ERROR_GEN_FAILURE);
        return 6;
    }
    return 0;
}
