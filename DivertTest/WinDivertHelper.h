#pragma once
#include "windivert.h"
namespace net {
    namespace driver {
        typedef struct _QuarantineModuleFunc
        {
            decltype(&WinDivertOpen) WinDivertOpen;
            decltype(&WinDivertRecv) WinDivertRecv;
            decltype(&WinDivertRecvEx) WinDivertRecvEx;
            decltype(&WinDivertSend) WinDivertSend;
            decltype(&WinDivertSetSocket) WinDivertSetSocket;
            decltype(&WinDivertSendEx) WinDivertSendEx;
            decltype(&WinDivertShutdown) WinDivertShutdown;
            decltype(&WinDivertClose) WinDivertClose;
            decltype(&WinDivertSetParam) WinDivertSetParam;
            decltype(&WinDivertGetParam) WinDivertGetParam;
            decltype(&WinDivertHelperHashPacket) WinDivertHelperHashPacket;
            decltype(&WinDivertHelperParsePacket) WinDivertHelperParsePacket;
            decltype(&WinDivertHelperParseIPv4Address) WinDivertHelperParseIPv4Address;
            decltype(&WinDivertHelperParseIPv6Address) WinDivertHelperParseIPv6Address;
            decltype(&WinDivertHelperFormatIPv4Address) WinDivertHelperFormatIPv4Address;
            decltype(&WinDivertHelperFormatIPv6Address) WinDivertHelperFormatIPv6Address;
            decltype(&WinDivertHelperCalcChecksums) WinDivertHelperCalcChecksums;
            decltype(&WinDivertHelperDecrementTTL) WinDivertHelperDecrementTTL;
            decltype(&WinDivertHelperCompileFilter) WinDivertHelperCompileFilter;
            decltype(&WinDivertHelperEvalFilter) WinDivertHelperEvalFilter;
            decltype(&WinDivertHelperFormatFilter) WinDivertHelperFormatFilter;
            decltype(&WinDivertHelperNtohs) WinDivertHelperNtohs;
            decltype(&WinDivertHelperHtons) WinDivertHelperHtons;
            decltype(&WinDivertHelperNtohl) WinDivertHelperNtohl;
            decltype(&WinDivertHelperHtonl) WinDivertHelperHtonl;
            decltype(&WinDivertHelperNtohll) WinDivertHelperNtohll;
            decltype(&WinDivertHelperHtonll) WinDivertHelperHtonll;
            decltype(&WinDivertHelperNtohIPv6Address) WinDivertHelperNtohIPv6Address;
            decltype(&WinDivertHelperHtonIPv6Address) WinDivertHelperHtonIPv6Address;
            decltype(&WinDivertHelperNtohIpv6Address) WinDivertHelperNtohIpv6Address;
            decltype(&WinDivertHelperHtonIpv6Address) WinDivertHelperHtonIpv6Address;
        }WinDivertModuleFunc;

        class WinDivertModule
        {
        public:
            WinDivertModule();
            ~WinDivertModule();

            void Destroy();


            bool Load(const std::wstring& path);
        public:
            WinDivertModuleFunc func_;
        private:
            HMODULE module_handle_ = nullptr;
            const wchar_t* module_name_ = L"WinDivertUser.dll";
            // dll 功能函数
        };
    }
}