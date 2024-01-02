#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS			//disable crt secure warnings
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <WinSock2.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <netlistmgr.h>


#include <iostream>
#include <stdio.h>
#include <string>

#include <mutex>


#include <vector>
#include <set>
#include <map>

#include "windivert.h"
#define CALLBACK    __stdcall
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

