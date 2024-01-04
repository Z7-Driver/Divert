// DivertTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "WinDivertHelper.h"
#include <log/blog.h>
#include <common.h>
#define MAXBUF  0xFFFF
class Packet {
public:
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    UINT8 protocol;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    PVOID payload;
    UINT payload_len;
};
#define INET6_ADDRSTRLEN    45
int main()
{
    common::log::init_log(L"DivertTest.log", true, true);
    std::wstring current_directory;
    wchar_t buff[MAX_PATH] = { 0 };
    size_t buff_size = _countof(buff);
    auto status = GetModuleFileNameW(GetModuleHandleW(nullptr), buff, buff_size);
    current_directory = buff;
    auto pos = current_directory.rfind(L'\\');
    if (pos != std::wstring::npos)
    {
        current_directory = current_directory.substr(0, pos);
    }

    net::driver::WinDivertModule divert_module_;
    divert_module_.Load(current_directory.c_str());
    const char* filter = "tcp == TRUE || udp == TRUE || icmp ==TRUE || icmpv6 == TRUE", * err_str;
    HANDLE divert_handle = divert_module_.func_.WinDivertOpen(filter, WINDIVERT_LAYER_SOCKET, 10, WINDIVERT_FLAG_RECV_ONLY | WINDIVERT_FLAG_DECISION);

    Packet* packet = new Packet();
    char local_addr_str[INET6_ADDRSTRLEN + 1], remote_addr_str[INET6_ADDRSTRLEN + 1];
    bool is_block = false;
    while (1)
    {
        memset(packet, 0, sizeof(Packet));
        memset(local_addr_str, 0, sizeof(local_addr_str));
        memset(remote_addr_str, 0, sizeof(remote_addr_str));

        if (!divert_module_.func_.WinDivertRecv(divert_handle, packet->packet, sizeof(packet->packet), &packet->packet_len,
            &packet->addr)) {
            BLOG(ERRORB) << "Failed to read packet (" << GetLastError() << ")" << std::endl;
            continue;
        }
        if (packet->addr.Layer != WINDIVERT_LAYER_SOCKET)
        {
            continue;
        }

        std::string event_desc = u8"UNKNOWN";
        std::string protocol_desc = u8"UNKNOWN";
        switch (packet->addr.Event)
        {
        case WINDIVERT_EVENT_SOCKET_BIND:
            event_desc = ("BIND");
            break;
        case WINDIVERT_EVENT_SOCKET_LISTEN:
            event_desc = ("LISTEN");
            break;
        case WINDIVERT_EVENT_SOCKET_CONNECT:
            event_desc = ("CONNECT");
            break;
        case WINDIVERT_EVENT_SOCKET_ACCEPT:
            event_desc = ("ACCEPT");
            break;
        case WINDIVERT_EVENT_SOCKET_CLOSE:
            event_desc = ("CLOSE");
            break;
        }
        divert_module_.func_.WinDivertHelperFormatIPv6Address(packet->addr.Socket.LocalAddr, local_addr_str,
            sizeof(local_addr_str));
        divert_module_.func_.WinDivertHelperFormatIPv6Address(packet->addr.Socket.RemoteAddr, remote_addr_str,
            sizeof(remote_addr_str));
        switch (packet->addr.Socket.Protocol)
        {
        case IPPROTO_TCP:
            protocol_desc = ("TCP");
            break;
        case IPPROTO_UDP:
            protocol_desc = ("UDP");
            break;
        case IPPROTO_ICMP:
            protocol_desc = ("ICMP");
            break;
        case IPPROTO_ICMPV6:
            protocol_desc = ("ICMPV6");
            break;
        }
        std::wstring process_name = common::process::GetProcessPathFromPid(packet->addr.Socket.ProcessId);
        if (process_name.length() > 0)
        {
            process_name = common::path::GetFileNameW(process_name);
        }
        std::string is_out = (packet->addr.Outbound == true) ? u8"out" : u8"in";
        UINT32 send_len = 0;
        if (packet->addr.Socket.Sync)
        {
            BLOG(INFO) << u8"[sync  " << is_out << u8" " << event_desc << u8"]" << protocol_desc << u8",process:" << common::string::SysWideToUTF8(process_name)
                << u8"(" << packet->addr.Socket.ProcessId << u8"),local:" << local_addr_str << u8":" << packet->addr.Socket.LocalPort
                << u8",remote:" << remote_addr_str << u8":" << packet->addr.Socket.RemotePort;
            packet->addr.Socket.IsUserBlock = FALSE;
            divert_module_.func_.WinDivertSetSocket(divert_handle, &packet->addr);
        }
        else
        {

            BLOG(INFO) << u8"[async " << is_out << u8" " << event_desc << u8"]" << protocol_desc << u8",process:" << common::string::SysWideToUTF8(process_name)
                << u8"(" << packet->addr.Socket.ProcessId << u8"),local:" << local_addr_str << u8":" << packet->addr.Socket.LocalPort
                << u8",remote:" << remote_addr_str << u8":" << packet->addr.Socket.RemotePort;
        }
    }
    if (packet)
    {
        delete packet;
    }
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
