#pragma once

//x64 - use $(SolutionDir)x64\Release\, x32 - 
#pragma comment(lib, "Meh.lib")

#ifndef _WIN64
#define MEH_API __stdcall
#else 
#define MEH_API __fastcall
#endif // !_WIN64
 
//SDK for some check
extern "C" __declspec(dllimport)  bool MEH_API MehIsDebuggerDetect();
extern "C" __declspec(dllimport)  bool MEH_API MehIsCRCValid();
extern "C" __declspec(dllimport)  bool MEH_API MehIsVMDetect();