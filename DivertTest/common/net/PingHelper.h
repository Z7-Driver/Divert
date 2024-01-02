#pragma once
#include "common/net/net_common.h"
namespace common {
    namespace net
    {
#define ECHO_REQUEST 8
#define ECHO_REPLY 0
        //ICMP报文由首部8B和数据段组成。
    //首部为定长的8个字节，前4个字节是通用部分（类型1B/代码1B/校验和2B），后4个字节随报文类型的不同有所差异。

        //类
        class CPing
        {
            //公共变量
        public:
            CPing();  //构造函数
            ~CPing(); //析构函数

            BOOL Ping(const std::string& szDestIP, PingReply* pPingReply = NULL, DWORD dwTimeout = 1000);

            //私有变量
        private:
            BOOL PingCoreIPv4(const std::string& szDestIP, PingReply* pPingReply, DWORD dwTimeout);
            BOOL PingCoreIPv6(const std::string& szDestIP, PingReply* pPingReply, DWORD dwTimeout);


        };
    }
}