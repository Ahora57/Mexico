#include <iostream>
#include <Windows.h>
#include "meh_sdk.h"
 
int main()
{
    uint32_t num = 1;

    num = __rdtsc();
    LoadLibraryW(L"Ws2_32.dll");

    if (MehIsCRCValid())
    {
        MessageBox
        (
            NULL,
            (LPCWSTR)L"CRC valid!\n",
            (LPCWSTR)L"Good",
            MB_ICONWARNING
        );
    }
    else
    {
        MessageBox
        (
            NULL,
            (LPCWSTR)L"CRC invalid!\n",
            (LPCWSTR)L"Bad",
            MB_ICONWARNING
        );
    }



    if (!MehIsDebuggerDetect())
    {
        MessageBox
        (
            NULL,
            (LPCWSTR)L"No debugger!\n",
            (LPCWSTR)L"Good",
            MB_ICONWARNING
        );
    }
    else
    {
        MessageBox
        (
            NULL,
            (LPCWSTR)L"Debugger detect!\n",
            (LPCWSTR)L"Bad",
            MB_ICONWARNING
        );
    }



    if (!MehIsVMDetect())
    {
        MessageBox
        (
            NULL,
            (LPCWSTR)L"No detect VM!\n",
            (LPCWSTR)L"Good",
            MB_ICONWARNING
        );
    }
    else
    {
        MessageBox
        (
            NULL,
            (LPCWSTR)L"Detect VM!\n",
            (LPCWSTR)L"Bad",
            MB_ICONWARNING
        );
    }


    Sleep(500);
    return EXIT_SUCCESS;
}