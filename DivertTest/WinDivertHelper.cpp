#include "WinDivertHelper.h"
#include "log/blog.h"
#define LOAD_FUNC(module_handle, func_, func_name)                                         \
	{                                                                                      \
		func_.func_name = (decltype(&func_name))GetProcAddress(module_handle, #func_name); \
		if (func_.func_name == nullptr)                                                    \
		{                                                                                  \
			break;                                                                         \
		}                                                                                  \
	}
namespace net
{
    namespace driver
    {
        WinDivertModule::WinDivertModule() : func_{ 0 }
        {
        }

        WinDivertModule::~WinDivertModule()
        {
        }
        void WinDivertModule::Destroy()
        {
            if (module_handle_ != nullptr)
            {
                memset(&func_, 0, sizeof(func_));

                FreeLibrary(module_handle_);
                module_handle_ = nullptr;
            }
        }



        bool WinDivertModule::Load(const std::wstring& path)
        {
            bool ret = false;

            do
            {
                if (module_handle_ != nullptr)
                {
                    ret = true;
                    break;
                }

                std::wstring module_path = path + L"\\" + module_name_;
                module_handle_ = LoadLibraryW(module_path.c_str());
                if (module_handle_ == nullptr)
                {
                    BLOGW(ERRORB) << L"Load " << module_path << L" failed" << L"errcode:" << GetLastError();
                    break;
                }




                LOAD_FUNC(module_handle_, func_, WinDivertOpen);
                LOAD_FUNC(module_handle_, func_, WinDivertRecv);
                LOAD_FUNC(module_handle_, func_, WinDivertRecvEx);
                LOAD_FUNC(module_handle_, func_, WinDivertSend);
                LOAD_FUNC(module_handle_, func_, WinDivertSendEx);
                LOAD_FUNC(module_handle_, func_, WinDivertSetSocket);
                LOAD_FUNC(module_handle_, func_, WinDivertShutdown);
                LOAD_FUNC(module_handle_, func_, WinDivertClose);
                LOAD_FUNC(module_handle_, func_, WinDivertSetParam);
                LOAD_FUNC(module_handle_, func_, WinDivertGetParam);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperHashPacket);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperParsePacket);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperParseIPv4Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperParseIPv6Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperFormatIPv4Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperFormatIPv6Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperCalcChecksums);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperDecrementTTL);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperCompileFilter);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperEvalFilter);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperFormatFilter);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperNtohs);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperHtons);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperNtohl);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperHtonl);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperNtohll);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperHtonll);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperNtohIPv6Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperHtonIPv6Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperNtohIpv6Address);
                LOAD_FUNC(module_handle_, func_, WinDivertHelperHtonIpv6Address);

                ret = true;
            } while (false);
            return ret;
        }
    }
}
#undef LOAD_FUNC