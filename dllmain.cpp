#include "Plugin_SDK.h"
#include "sha1.h"
#include "sha256.h"
#include <intrin.h>

static bool isEnabled = false;

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        int CPUInfo[4];
        __cpuid(CPUInfo, 0);
        if (CPUInfo[0] >= 7) {
            __cpuidex(CPUInfo, 7, 0);
            if (CPUInfo[1] & (1 << 29)) isEnabled = true;
        }
    }
    return TRUE;
}

BOOL HSPCALL HSP_Initialize(CPHSP_InitInfo cpInitInfo, PHSP_PluginBasicInfo pPluginBasicInfo) {
    static const GUID pluginGuid{
        0xcf99b91b, 0x0c8f, 0x4f6f, { 0x80, 0xca, 0x70, 0x70, 0x10, 0xab, 0x3f, 0x25 }
    };
    pPluginBasicInfo->eHSPFuncFlags = HSPFuncFlags_Hash;
    pPluginBasicInfo->pGuid = &pluginGuid;
    pPluginBasicInfo->pluginInterfaceVer = HSP_INTERFACE_VER;
    pPluginBasicInfo->pluginSDKVer = HSP_SDK_VER;
    return TRUE;
}

LRESULT HSPCALL HSP_PluginFunc(HSPPFMsg uMsg, WPARAM wParam, LPARAM lParam) {
    if (!isEnabled) return FALSE;

    if (uMsg == HSPPFMsg_Hash_GetSupportAlgCount) return 3;

    auto AlgID = (uint32_t)lParam;

    if (AlgID == 0) {
        static const char16_t* hashName = (const char16_t*)L"SHA-1 (SHA-NI)";

        static const GUID hashGuid{
            0x7131051a, 0x303e, 0x4505, { 0xaf, 0x39, 0x59, 0xbb, 0xe3, 0x67, 0x62, 0xe5 }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 64;
            pAlgInfo->DigestSize = 20;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = new sha1_state();
                sha1_init(state);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                sha1_update((sha1_state*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                sha1_finalize((sha1_state*)state, digest, getOctets);
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                sha1_init((sha1_state*)state);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                delete (sha1_state*)state;
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                return new sha1_state(*(sha1_state*)state);
            };
            return TRUE;
        }
    }

    if (AlgID == 1) {
        static const char16_t* hashName = (const char16_t*)L"SHA-224 (SHA-NI)";

        static const GUID hashGuid{
            0x87573a04, 0x80b7, 0x4a59, { 0xb4, 0x2a, 0xc0, 0x56, 0xb0, 0xa7, 0x7f, 0xc6 }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 64;
            pAlgInfo->DigestSize = 28;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = new sha256_state();
                sha224_init(state);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                sha256_update((sha256_state*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                sha224_finalize((sha256_state*)state, digest, getOctets);
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                sha224_init((sha256_state*)state);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                delete (sha256_state*)state;
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                return new sha256_state(*(sha256_state*)state);
            };
            return TRUE;
        }
    }

    if (AlgID == 2) {
        static const char16_t* hashName = (const char16_t*)L"SHA-256 (SHA-NI)";

        static const GUID hashGuid{
            0x59845325, 0x1bd5, 0x453e, { 0xb1, 0x61, 0xa0, 0x40, 0xac, 0x47, 0xba, 0xd9 }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 64;
            pAlgInfo->DigestSize = 32;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = new sha256_state();
                sha256_init(state);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                sha256_update((sha256_state*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                sha256_finalize((sha256_state*)state, digest, getOctets);
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                sha256_init((sha256_state*)state);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                delete (sha256_state*)state;
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                return new sha256_state(*(sha256_state*)state);
            };
            return TRUE;
        }
    }
    return FALSE;
}
