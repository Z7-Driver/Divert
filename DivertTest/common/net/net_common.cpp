#include "net_common.h"
#include <common/log/blog.h>
#include <common/common.h>

namespace common {
    namespace net
    {
        // MARK: ip_addr_t
        ip_addr_t::operator bool() const {
            auto len = data.size();
            return len == 4 || len == 16;
        }

        bool ip_addr_t::operator==(const ip_addr_t& other) const {
            auto len = data.size();
            if (len == 0 || len != other.data.size()) return false;

            for (auto i = 0; i < len; i++) {
                if (data.at(i) != other.data.at(i))
                    return false;
            }
            return true;
        }

        bool ip_addr_t::operator<(const ip_addr_t& other) const {
            auto len = data.size();
            if (len != other.data.size()) {
                return len < other.data.size();
            }

            for (auto i = 0; i < len; i++) {
                uint8_t tb = data.at(i), ob = other.data.at(i);
                if (tb > ob) {
                    return false;
                }
                if (data.at(i) == other.data.at(i)) {
                    continue;
                }
                return true;
            }
            return false;
        }

        bool ip_addr_t::operator<=(const ip_addr_t& other) const {
            auto len = data.size();
            if (len != other.data.size()) {
                return len < other.data.size();
            }

            return *this < other || *this == other;
        }

        bool ip_addr_t::operator>=(const ip_addr_t& other) const {
            auto len = data.size();
            if (len != other.data.size()) {
                return len > other.data.size();
            }

            return !(*this < other);
        }

        const ip_addr_t& ip_addr_t::LoopbackV4() {
            static ip_addr_t v4;
            static std::once_flag init_flag;
            std::call_once(init_flag, [&]() {
                v4.data = { 127, 0, 0, 1 };
                });
            return v4;
        }
        const ip_addr_t& ip_addr_t::LoopbackV6() {
            static ip_addr_t v6;
            static std::once_flag init_flag;
            std::call_once(init_flag, [&]() {
                v6.data = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
                });
            return v6;
        }
        bool IsIpv4AddressType(const std::string& input)
        {
            std::string ip_str = input;
            auto mask_segm_ops = ip_str.find(u8'/');
            if (mask_segm_ops != ip_str.npos)
            {
                ip_str = ip_str.substr(0, mask_segm_ops);
            }
            int len = ip_str.size();
            int n = 0;
            for (int i = 0; i < len; i++) {
                if (ip_str[i] != '.' && (ip_str[i] < '0' || ip_str[i]>'9')) return false;//如果出现字母，那么非法

                if (i < len - 1 && ip_str[i] == ip_str[i + 1] && ip_str[i] == '.') return false;//边界条件,如果两个..出现在一起显然是非法的，我们这个逻辑会这个非法们当成‘ ’分割的时候忽略(直接想不到，调试直接发现的)

            }
            std::vector<std::string> ip_segms = common::string::strSplit(ip_str, u8".");
            if (ip_segms.size() == 0)
            {
                return false;
            }
            bool ret = true;
            for (const auto& iter : ip_segms)
            {
                unsigned long ip_segm_ul = 0;
                try
                {
                    char* endptr;
                    ip_segm_ul = std::strtoul(iter.c_str(), &endptr, 10);
                }
                catch (const std::exception&)
                {
                    ret = false;
                }
                if (ip_segm_ul > 255) {
                    ret = false;
                }
                if (ret == false)
                {
                    break;
                }
            }
            return ret;
        }

        bool IsCidrIpAdress(const std::string& queryIP)
        {

            if (queryIP.find('/') != std::string::npos)
            {
                return true;
            }
            return false;
        }
        bool IsIpv6AddressType(const std::string& input)
        {
            std::string ip_str = input;
            auto mask_segm_ops = ip_str.find(u8'/');
            if (mask_segm_ops != ip_str.npos)
            {
                ip_str = ip_str.substr(0, mask_segm_ops);
            }
            int n = 0;
            int len = ip_str.size();
            for (int i = 0; i < len; i++) {
                if (ip_str[i] != ':' && ((ip_str[i] > 'f' && ip_str[i] <= 'z') || (ip_str[i] > 'F' && ip_str[i] < 'Z'))) return false;
            }
            std::vector<std::string> ip_segms = common::string::strSplit(ip_str, u8":");
            if (ip_segms.size() == 0)
            {
                return false;
            }
            for (const auto& iter : ip_segms)
            {
                if (iter.size() > 4)
                {
                    return false;
                }
            }
            return true;
        }
        IP_ADDRESS_TYPE GetValidIPAddressType(const std::string& queryIP) {
            if (queryIP.find(u8'.') != queryIP.npos)
            {

                if (IsIpv4AddressType(queryIP))
                {
                    return IP_ADDRESS_V4;
                }
                else
                {
                    return IP_ADDRESS_UNKNOWN;
                }
            }
            else if (queryIP.find(u8':') != queryIP.npos)
            {
                if (IsIpv6AddressType(queryIP))
                {
                    return IP_ADDRESS_V6;
                }
                else
                {
                    return IP_ADDRESS_UNKNOWN;
                }
            }

            return IP_ADDRESS_UNKNOWN;

        }

        BOOL IsPhysicalMac(const std::wstring& adapter_name)
        {

            REGSAM samDesired = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
            BOOL is_wow_64_process = true;
            IsWow64Process(GetCurrentProcess(), &is_wow_64_process);
            if (is_wow_64_process)
            {
                samDesired = samDesired | KEY_WOW64_64KEY;
            }
            LPCTSTR lpszKey = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}";
            HKEY hSubKey = NULL;
            if (::RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszKey, 0, samDesired, &hSubKey) != ERROR_SUCCESS) {
                return FALSE;
            }
            BOOL nRet = FALSE, bFind = FALSE;

            TCHAR achClass[MAX_PATH] = L"";
            DWORD cchClassName = MAX_PATH;
            DWORD cSubKeys = 0;
            DWORD cbMaxSubKey;
            DWORD cchMaxClass;
            DWORD cValues;
            DWORD cchMaxValue;
            DWORD cbMaxValueData;
            DWORD cbSecurityDescriptor;
            FILETIME ftLastWriteTime;
            if (::RegQueryInfoKey(hSubKey, achClass, &cchClassName, NULL,
                &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue,
                &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime) == ERROR_SUCCESS) {
                for (size_t i = 0; i < cSubKeys; i++)
                {
                    TCHAR achKey[MAX_PATH] = L"";
                    DWORD achName = MAX_PATH;
                    LSTATUS lp = ::RegEnumKeyEx(hSubKey, i, achKey, &achName,
                        NULL, NULL, NULL, &ftLastWriteTime);
                    if (lp == ERROR_SUCCESS) {
                        HKEY hachKey = NULL;
                        if (::RegOpenKeyEx(hSubKey, achKey, 0, KEY_QUERY_VALUE, &hachKey) == ERROR_SUCCESS) {
                            DWORD dwType = 0, dwSize = 0, dwValue = 0;
                            ::RegQueryValueEx(hachKey, L"NetCfgInstanceId", NULL, &dwType, NULL, &dwSize);
                            if (dwType == REG_SZ && dwSize > 0)
                            {
                                TCHAR lpszValue[MAX_PATH] = L"";
                                LONG lRes = ::RegQueryValueEx(hachKey, L"NetCfgInstanceId", NULL, &dwType, (LPBYTE)lpszValue, &dwSize);
                                if (_wcsicmp(lpszValue, adapter_name.c_str()) == 0) {
                                    bFind = TRUE;
                                    dwType = REG_DWORD;
                                    //dwSize = sizeof(DWORD);
                                    LONG lRes = ::RegQueryValueEx(hachKey, L"Characteristics", NULL, &dwType, (LPBYTE)&dwValue, &dwSize);
                                    if (dwValue & 0x04) {
                                        nRet = TRUE;
                                    }
                                }
                            }
                            ::RegCloseKey(hachKey);
                            if (bFind || nRet) {
                                break;
                            }
                        }
                    }
                }
            }
            ::RegCloseKey(hSubKey);

            return nRet;
        }

        bool GetAllAdapterInfo(std::vector<AdapterInfo>& adapter_infos)
        {
            ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;//包括 IPV4 ，IPV6 网关
            ULONG family = AF_UNSPEC;//返回包括 IPV4 和 IPV6 地址
            PIP_ADAPTER_ADDRESSES pAddresses = NULL;
            ULONG outBufLen = 0;
            DWORD dwRetVal = 0;
            PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
            PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
            PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
            IP_ADAPTER_DNS_SERVER_ADDRESS* pDnServer = NULL;
            IP_ADAPTER_PREFIX* pPrefix = NULL;
            outBufLen = 15000;
            do
            {
                pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
                if (pAddresses == NULL)
                    return false;
                dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
                if (dwRetVal == ERROR_BUFFER_OVERFLOW)
                {
                    free(pAddresses);
                    pAddresses = NULL;
                }
                else
                    break;
            } while (dwRetVal == ERROR_BUFFER_OVERFLOW);
            if (dwRetVal == NO_ERROR)
            {
                pCurrAddresses = pAddresses;
                while (pCurrAddresses)
                {
                    AdapterInfo adapter_item = {};
                    pUnicast = pCurrAddresses->FirstUnicastAddress;
                    while (pUnicast)//单播IP
                    {
                        ip_addr_t exact_ip;
                        net::ParseIp(*(pUnicast->Address.lpSockaddr), exact_ip);
                        adapter_item.ip_addr.insert(exact_ip);
                        pUnicast = pUnicast->Next;
                    }
                    pDnServer = pCurrAddresses->FirstDnsServerAddress;
                    while (pDnServer)//DNS
                    {
                        ip_addr_t exact_ip;
                        net::ParseIp(*(pDnServer->Address.lpSockaddr), exact_ip);
                        adapter_item.name_servers.insert(exact_ip);
                        pDnServer = pDnServer->Next;
                    }
                    if (pCurrAddresses->FriendlyName)
                    {
                        adapter_item.friendly_name = common::string::SysWideToUTF8(pCurrAddresses->FriendlyName);
                    }
                    if (pCurrAddresses->Description)
                    {
                        adapter_item.description = common::string::SysWideToUTF8(pCurrAddresses->Description);
                    }
                    adapter_item.is_physical_mac = IsPhysicalMac(common::string::SysUTF8ToWide(pCurrAddresses->AdapterName));
                    adapter_item.is_active = (pCurrAddresses->OperStatus == IF_OPER_STATUS::IfOperStatusUp);
                    adapter_infos.push_back(adapter_item);
                    pCurrAddresses = pCurrAddresses->Next;
                }
            }
            if (pAddresses)
                free(pAddresses);
            return adapter_infos.size() > 0;
        }

        bool IpStringToAddr(const std::string& ip_str, ip_addr_t& output_ip) {
            if (ip_str.find(':') != std::string::npos) {
                // The string is an IPv6 address
                output_ip.data.resize(16);
                if (inet_pton(AF_INET6, ip_str.c_str(), output_ip.data.data()) == 1) {
                    return true;
                }
            }
            else if (ip_str.find('.') != std::string::npos) {
                // The string is an IPv4 address
                output_ip.data.resize(4);
                if (inet_pton(AF_INET, ip_str.c_str(), output_ip.data.data()) == 1) {
                    return true;
                }
            }
            return false;
        }
        void SockAddr2String(const SOCKADDR& input, std::string& output) {
            char str[INET6_ADDRSTRLEN + 6] = { 0 };
            void* in_addr;

            if (input.sa_family == AF_INET) {
                in_addr = &(((struct sockaddr_in&)input).sin_addr);
            }
            else {
                in_addr = &(((struct sockaddr_in6&)input).sin6_addr);
            }

            inet_ntop(input.sa_family, in_addr, str, sizeof(str));
            output = str;
        }
        bool ParseIp(const SOCKADDR& input, ip_addr_t& exact_ip) {
            if (input.sa_family == AF_INET) {
                // IPv4
                exact_ip.data.resize(4);
                SOCKADDR_IN* ipv4 = (SOCKADDR_IN*)&input;
                memcpy(exact_ip.data.data(), &(ipv4->sin_addr), 4);
            }
            else if (input.sa_family == AF_INET6) {
                // IPv6
                exact_ip.data.resize(16);
                SOCKADDR_IN6* ipv6 = (SOCKADDR_IN6*)&input;
                memcpy(exact_ip.data.data(), &(ipv6->sin6_addr), 16);
            }
            else {
                // Unknown address family
                return false;
            }

            return true;
        }


        std::string IpToString(const ip_addr_t& ip)
        {
            char buffer[INET6_ADDRSTRLEN] = { 0 };
            if (ip.data.size() == 4) {
                // IPv4
                if (inet_ntop(AF_INET, ip.data.data(), buffer, sizeof(buffer)) == NULL) {
                    return "";
                }
            }
            else if (ip.data.size() == 16) {
                // IPv6
                if (inet_ntop(AF_INET6, ip.data.data(), buffer, sizeof(buffer)) == NULL) {
                    return "";
                }
            }
            else {
                // Invalid IP address
                return "";
            }
            return std::string(buffer);
        }

        bool ParseIpAddressRange(const std::string& queryIP, ip_addr_t& start_ip, ip_addr_t& end_ip)
        {
            bool ret = false;
            do
            {
                ip_addr_t pre_ip, post_ip;

                size_t seg_ops = queryIP.find('-');
                if (seg_ops != queryIP.npos)
                {
                    std::string pre_ip_str = queryIP.substr(0, seg_ops);
                    std::string post_ip_str = queryIP.substr(seg_ops + 1);
                    if (!ParseIp(pre_ip_str, pre_ip))
                    {
                        break;
                    }
                    if (!ParseIp(post_ip_str, post_ip))
                    {
                        break;
                    }
                    if (pre_ip <= post_ip)
                    {
                        start_ip = pre_ip;
                        end_ip = post_ip;
                    }
                    else
                    {
                        start_ip = post_ip;
                        end_ip = pre_ip;
                    }
                    ret = true;
                }
                else
                {
                    if (!ParseIp(queryIP, pre_ip))
                    {
                        break;
                    }
                    start_ip = pre_ip;
                    end_ip = pre_ip;
                    ret = true;
                }
            } while (false);
            return ret;
        }
        bool ParseIp(const std::string& input, ip_addr_t& exact_ip)
        {
            if (input.find(':') != std::string::npos) {
                // IPv6
                exact_ip.data.resize(16);
                if (inet_pton(AF_INET6, input.c_str(), exact_ip.data.data()) != 1) {
                    BLOG(ERRORB) << u8"Parse Ipv4 fail,ip:" << input;
                    return false;
                }
            }
            else {
                // IPv4
                exact_ip.data.resize(4);
                if (inet_pton(AF_INET, input.c_str(), exact_ip.data.data()) != 1) {
                    BLOG(ERRORB) << u8"Parse Ipv6 fail,ip:" << input;
                    return false;
                }
            }
            return true;
        }
        bool ParseCidr(const std::string& input, ip_addr_t& cidr_ip, uint32_t& cidr_mask)
        {


            size_t mask_str_ops = input.find('/');
            if (mask_str_ops == input.npos || mask_str_ops == input.length())
            {
                return false;
            }

            std::string ip_str = input.substr(0, mask_str_ops);
            std::string mask_str = input.substr(mask_str_ops + 1);
            ip_str += '\0';
            mask_str += '\0';
            cidr_mask = atoi(mask_str.c_str());

            if (input.find(':') != input.npos) {
                // IPv6
                cidr_ip.data.resize(16);
                if (inet_pton(AF_INET6, ip_str.c_str(), cidr_ip.data.data()) != 1) {
                    return false;
                }
            }
            else {
                // IPv4
                cidr_ip.data.resize(4);
                if (inet_pton(AF_INET, ip_str.c_str(), cidr_ip.data.data()) != 1) {
                    return false;
                }
            }

            return true;
        }
        bool GetRealIpByDomainName(const std::string& domain, std::vector<std::string>& ips)
        {

            struct addrinfo hints, * res, * rp;
            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;

            DWORD dwRetval = getaddrinfo(domain.c_str(), NULL, &hints, &res);

            if (dwRetval)
            {
                BLOG(INFO) << u8"error code:" << GetLastError() << u8",domain:" << domain;
                return false;
            }
            for (rp = res; rp != NULL; rp = rp->ai_next)
            {
                if (rp->ai_family == AF_INET)
                {
                    char ipbuf[16] = {};
                    sockaddr_in* addr_v4 = (struct sockaddr_in*)rp->ai_addr;
                    inet_ntop(AF_INET, &addr_v4->sin_addr, ipbuf, 16);
                    ips.push_back(ipbuf);
                }
                else
                {
                    char ip6buf[64] = {};
                    sockaddr_in6* addr_v6 = (struct sockaddr_in6*)rp->ai_addr;
                    inet_ntop(AF_INET6, &addr_v6->sin6_addr, ip6buf, 64);
                    ips.push_back(ip6buf);

                }
            }
            freeaddrinfo(res);

            return ips.size() > 0;
        }


    }
}