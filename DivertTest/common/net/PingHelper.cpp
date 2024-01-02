#include "PingHelper.h"
#include <ws2tcpip.h>
#include <common/log/blog.h>
#include <icmpapi.h>
namespace common {
    namespace net
    {
#define DEF_PACKET_SIZE  32
        //::表示类作用域。为避免不同的类有名称相同的成员而采用作用域的方式进行区分。
        CPing::CPing()
        {
            WSADATA WSAData;
            WSAStartup(MAKEWORD(2, 2), &WSAData);

        }


        CPing::~CPing()
        {
            WSACleanup();

        }
        BOOL CPing::Ping(const std::string& szDestIP, PingReply* pPingReply, DWORD dwTimeout)
        {
            if (!szDestIP.empty())	//远端IP非空
            {
                IP_ADDRESS_TYPE add_type = net::GetValidIPAddressType(szDestIP);
                if (add_type == IP_ADDRESS_TYPE::IP_ADDRESS_V4)
                {
                    return PingCoreIPv4(szDestIP, pPingReply, dwTimeout);
                }
                else if (add_type == IP_ADDRESS_TYPE::IP_ADDRESS_V6)
                {
                    return PingCoreIPv6(szDestIP, pPingReply, dwTimeout);
                }
                else//猜测是domain需要解析
                {
                    std::vector<std::string> ips;
                    GetRealIpByDomainName(szDestIP, ips);
                    for (auto iter_ip : ips)
                    {
                        IP_ADDRESS_TYPE domain_add_type = net::GetValidIPAddressType(iter_ip);
                        bool ping_ret = false;
                        if (domain_add_type == IP_ADDRESS_TYPE::IP_ADDRESS_V4)
                        {
                            ping_ret = PingCoreIPv4(iter_ip, pPingReply, dwTimeout);
                        }
                        else if (domain_add_type == IP_ADDRESS_TYPE::IP_ADDRESS_V6)
                        {
                            ping_ret = PingCoreIPv6(iter_ip, pPingReply, dwTimeout);
                        }
                        if (ping_ret)
                        {
                            return true;
                        }
                    }
                }
            }
            return FALSE;           //远端IP为空，false
        }
        BOOL CPing::PingCoreIPv4(const std::string& szDestIP, PingReply* pPingReply, DWORD dwTimeout)
        {
            BOOL ret = false;

            //配置套接字SOCKET
            sockaddr_in sockaddrDest = {};                    //sockaddr_in是internet环境下的套接字地址。定义在ws2def.h中的结构体
            sockaddrDest.sin_family = AF_INET;           //地址族（Address Family）：网络类型
            inet_pton(AF_INET, szDestIP.c_str(), &sockaddrDest.sin_addr);
            int nSockaddrDestSize = sizeof(sockaddrDest);//大小
            HANDLE icmp_handle = IcmpCreateFile();
            if (icmp_handle == INVALID_HANDLE_VALUE) {
                BLOG(ERRORB) << u8"create icmp v4 failed:" << GetLastError();
                return false;
            }
            IP_OPTION_INFORMATION ipInfo = { 255, 0, 0, 0, NULL };
            char EchoRequest[64] = u8"ICMP delay detection";
            DWORD EchoReply_size = sizeof(EchoRequest) + sizeof(ICMP_ECHO_REPLY) + 8;
            char* EchoReply = (char*)malloc(EchoReply_size);
            memset(EchoReply, 0, EchoReply_size);
            do
            {

                //定义sourceAddress信息
                DWORD icmp_send_result = IcmpSendEcho(icmp_handle, sockaddrDest.sin_addr.S_un.S_addr, EchoRequest, sizeof(EchoRequest), NULL, EchoReply, EchoReply_size, dwTimeout);
                if (icmp_send_result == IP_BUF_TOO_SMALL)
                {
                    EchoReply_size = EchoReply_size * 2;
                    free(EchoReply);
                    EchoReply = (char*)malloc(EchoReply_size);
                    icmp_send_result = IcmpSendEcho(icmp_handle, sockaddrDest.sin_addr.S_un.S_addr, &EchoRequest, sizeof(EchoRequest), NULL, EchoReply, EchoReply_size, dwTimeout);
                }
                if (icmp_send_result == 0)
                {
                    BLOG(ERRORB) << u8"IcmpSendEcho failed:" << GetLastError();
                    return ret;
                }
                DWORD icmp_Parse_result = Icmp6ParseReplies(EchoReply, EchoReply_size);
                if (icmp_Parse_result == 0)
                {
                    BLOG(ERRORB) << u8"Icmp6ParseReplies failed:" << GetLastError();
                    break;
                }
                if (pPingReply)
                {
                    for (size_t index = 0; index < icmp_Parse_result; index++)
                    {

                        ICMP_ECHO_REPLY& replay_ptr = ((ICMP_ECHO_REPLY*)EchoReply)[index];

                        pPingReply->m_dwRoundTripTime = (pPingReply->m_dwRoundTripTime + replay_ptr.RoundTripTime) / 2;

                    }
                }
                ret = true;
            } while (false);
            if (EchoReply != NULL)
            {
                free(EchoReply);
                EchoReply = NULL;
            }
            IcmpCloseHandle(icmp_handle);
            return ret;

        }

        BOOL CPing::PingCoreIPv6(const std::string& szDestIP, PingReply* pPingReply, DWORD dwTimeout)
        {
            BOOL ret = false;

            //配置套接字SOCKET
            sockaddr_in6 sockaddrDest = {};                    //sockaddr_in是internet环境下的套接字地址。定义在ws2def.h中的结构体
            sockaddrDest.sin6_family = AF_INET6;           //地址族（Address Family）：网络类型
            inet_pton(AF_INET6, szDestIP.c_str(), &sockaddrDest.sin6_addr);
            int nSockaddrDestSize = sizeof(sockaddrDest);//大小
            HANDLE icmp_handle = Icmp6CreateFile();
            if (icmp_handle == INVALID_HANDLE_VALUE) {
                BLOG(ERRORB) << u8"create icmp v6 failed:" << GetLastError();
                return false;
            }
            IP_OPTION_INFORMATION ipInfo = { 255, 0, 0, 0, NULL };
            char EchoRequest[64] = u8"ICMP delay detection";
            DWORD EchoReply_size = sizeof(EchoRequest) + sizeof(ICMP_ECHO_REPLY) + 8;
            char* EchoReply = (char*)malloc(EchoReply_size);
            do
            {

                //定义sourceAddress信息
                struct sockaddr_in6 sa6Source = {};
                sa6Source.sin6_family = AF_INET6;
                sa6Source.sin6_flowinfo = 0;
                sa6Source.sin6_port = 0;
                sa6Source.sin6_scope_id = 0;
                sa6Source.sin6_addr = in6addr_any;
                DWORD icmp_send_result = Icmp6SendEcho2(icmp_handle, NULL, NULL, NULL, &sa6Source, &sockaddrDest, &EchoRequest, sizeof(EchoRequest), &ipInfo, EchoReply, EchoReply_size, dwTimeout);
                if (icmp_send_result == IP_BUF_TOO_SMALL)
                {
                    EchoReply_size = EchoReply_size * 2;
                    free(EchoReply);
                    EchoReply = (char*)malloc(EchoReply_size);
                    icmp_send_result = Icmp6SendEcho2(icmp_handle, NULL, NULL, NULL, &sa6Source, &sockaddrDest, &EchoRequest, sizeof(EchoRequest), &ipInfo, EchoReply, EchoReply_size, dwTimeout);
                }
                if (icmp_send_result == 0)
                {
                    BLOG(ERRORB) << u8"Icmp6SendEcho2 failed:" << GetLastError();
                    return ret;
                }
                DWORD icmp_Parse_result = Icmp6ParseReplies(EchoReply, EchoReply_size);
                if (icmp_Parse_result == 0)
                {
                    BLOG(ERRORB) << u8"Icmp6ParseReplies failed:" << GetLastError();
                    break;
                }
                if (pPingReply)
                {
                    for (size_t index = 0; index < icmp_Parse_result; index++)
                    {

                        ICMPV6_ECHO_REPLY& replay_ptr = ((ICMPV6_ECHO_REPLY*)EchoReply)[index];

                        pPingReply->m_dwRoundTripTime = (pPingReply->m_dwRoundTripTime + replay_ptr.RoundTripTime) / 2;

                    }
                }
                ret = true;
            } while (false);
            if (EchoReply != NULL)
            {
                free(EchoReply);
                EchoReply = NULL;
            }
            IcmpCloseHandle(icmp_handle);
            return ret;
        }


    }
}