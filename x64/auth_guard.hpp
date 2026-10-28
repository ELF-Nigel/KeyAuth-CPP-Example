#pragma once
#include "auth.hpp"

inline bool checkAuthenticated(KeyAuth::api& app) {
    app.check();
    return app.response.success && app.authenticated();
}
inline bool configureSafeDllSearch() {
    const auto kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) return false;
    using SetDirectories = BOOL (WINAPI*)(DWORD);
    const auto set_directories = reinterpret_cast<SetDirectories>(GetProcAddress(kernel, "SetDefaultDllDirectories"));
    return set_directories && set_directories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) != FALSE;
}
