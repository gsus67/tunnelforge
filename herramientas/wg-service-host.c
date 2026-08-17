// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
// Host nativo mínimo para tunnel.dll. Se compila en GitHub Actions y luego
// queda embebido dentro de Conectar-Gateway.exe junto con los DLL oficiales.
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define WG_PATH_CAP 32768

typedef BOOL (__cdecl *WireGuardTunnelServiceFn)(LPCWSTR configFile);

static void wgLogPath(LPCWSTR configPath, wchar_t out[WG_PATH_CAP])
{
    if (!configPath || wcslen(configPath) + 24 >= WG_PATH_CAP) {
        out[0] = L'\0';
        return;
    }
    wcscpy_s(out, WG_PATH_CAP, configPath);
    wcscat_s(out, WG_PATH_CAP, L".service-host.log");
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

int wmain(int argc, wchar_t **argv)
{
    if (argc != 3 || _wcsicmp(argv[1], L"/service") != 0)
        return 2;

    LPCWSTR configPath = argv[2];
    wchar_t exePath[WG_PATH_CAP];
    DWORD n = GetModuleFileNameW(NULL, exePath, WG_PATH_CAP);
    if (!n || n >= WG_PATH_CAP) {
        DWORD err = GetLastError();
        wgWriteError(configPath, L"GetModuleFileNameW", err ? err : ERROR_INSUFFICIENT_BUFFER);
        return 3;
    }

    wchar_t *slash = wcsrchr(exePath, L'\\');
    if (!slash) {
        wgWriteError(configPath, L"resolver directorio del host", ERROR_BAD_PATHNAME);
        return 3;
    }
    *slash = L'\0';

    wchar_t tunnelPath[WG_PATH_CAP];
    if (wcslen(exePath) + 12 >= WG_PATH_CAP) {
        wgWriteError(configPath, L"ruta tunnel.dll", ERROR_BUFFER_OVERFLOW);
        return 3;
    }
    wcscpy_s(tunnelPath, WG_PATH_CAP, exePath);
    wcscat_s(tunnelPath, WG_PATH_CAP, L"\\tunnel.dll");

    // LOAD_WITH_ALTERED_SEARCH_PATH hace que las dependencias de tunnel.dll,
    // incluido wireguard.dll, se busquen también en este mismo directorio.
    HMODULE tunnel = LoadLibraryExW(tunnelPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!tunnel) {
        DWORD err = GetLastError();
        wgWriteError(configPath, L"LoadLibraryExW(tunnel.dll)", err);
        return 4;
    }

    WireGuardTunnelServiceFn tunnelService =
        (WireGuardTunnelServiceFn)(void *)GetProcAddress(tunnel, "WireGuardTunnelService");
    if (!tunnelService) {
        DWORD err = GetLastError();
        wgWriteError(configPath, L"GetProcAddress(WireGuardTunnelService)", err);
        FreeLibrary(tunnel);
        return 5;
    }

    wgClearError(configPath);
    SetLastError(ERROR_SUCCESS);
    BOOL ok = tunnelService(configPath);
    DWORD err = GetLastError();
    FreeLibrary(tunnel);
    if (!ok) {
        wgWriteError(configPath, L"WireGuardTunnelService", err ? err : ERROR_GEN_FAILURE);
        return 6;
    }
    return 0;
}
