#pragma once
#define _CRT_SECURE_NO_WARNINGS			//disable crt secure warnings
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <Shlwapi.h>
#include <winver.h>
#include <psapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <SoftPub.h>
#include <winioctl.h>
#include <TlHelp32.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <list>
#include <iostream>
#include <algorithm>
#include <sstream>


#include <mutex>
#include <shared_mutex>
#include <memory>

#include <thirdparty/json/json.hpp>

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")
/*
#include <stdint.h>
#include <type_traits>
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
*/