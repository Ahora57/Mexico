 #include <Windows.h>

#ifndef _WIN64
#define MEH_API __stdcall
#else 
#define MEH_API __fastcall
#endif // !_WIN64

//Use for create API in .lib file and use
extern "C" __declspec(dllexport)  bool MEH_API MehIsDebuggerDetect()
{
    return false;
}

extern "C" __declspec(dllexport)  bool MEH_API MehIsCRCValid()
{
    return true;
}

extern "C" __declspec(dllexport)  bool MEH_API MehIsVMDetect()
{
    return false;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

