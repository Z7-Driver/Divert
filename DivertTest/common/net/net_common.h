#pragma once

namespace common {
    namespace net
    {

        typedef struct _ip_addr {
            std::vector<uint8_t> data;

            _ip_addr() {}
            _ip_addr(const _ip_addr& other) {
                data = other.data;
            }
            _ip_addr(_ip_addr&& other) {
                data = std::move(other.data);
            }
            _ip_addr& operator=(const _ip_addr& other) {
                data = other.data;
                return *this;
            }
            _ip_addr& operator=(_ip_addr&& other) {
                data = std::move(other.data);
                return *this;
            }

            explicit operator bool() const;
            bool operator==(const _ip_addr& other) const;
            bool operator<(const _ip_addr& other) const;
            bool operator<=(const _ip_addr& other) const;
            bool operator>=(const _ip_addr& other) const;

            static const _ip_addr& LoopbackV4();
            static const _ip_addr& LoopbackV6();
        } ip_addr_t;
        struct PingReply
        {
            DWORD m_dwRoundTripTime;//平均时间差		  4B  (word是2字节)
        };
        struct AdapterInfo
        {
            std::string friendly_name;
            std::string description;
            std::set<ip_addr_t> ip_addr;
            std::set<ip_addr_t> name_servers;
            bool is_physical_mac;
            bool is_active;

        };
        enum IP_ADDRESS_TYPE
        {
            IP_ADDRESS_UNKNOWN = 0,
            IP_ADDRESS_V4 = 1,
            IP_ADDRESS_V6 = 2,

        };
        BOOL IsPhysicalMac(const std::wstring& adapter_name);

        IP_ADDRESS_TYPE GetValidIPAddressType(const std::string& queryIP);
        bool IsIpv4AddressType(const std::string& queryIP);
        bool IsIpv6AddressType(const std::string& queryIP);
        bool IsCidrIpAdress(const std::string& queryIP);
        bool GetAllAdapterInfo(std::vector<AdapterInfo>& adapter_infos);
        void SockAddr2String(const SOCKADDR& input, std::string& output);
        std::string IpToString(const ip_addr_t& ip);
        bool IpStringToAddr(const std::string& ip_str, ip_addr_t& output_ip);
        bool ParseCidr(const std::string& input, ip_addr_t& cidr_ip, uint32_t& cidr_mask);
        bool ParseIpAddressRange(const std::string& queryIP, ip_addr_t& start_ip, ip_addr_t& end_ip);
        bool ParseIp(const std::string& input, ip_addr_t& exact_ip);
        bool ParseIp(const SOCKADDR& input, ip_addr_t& exact_ip);
        bool GetRealIpByDomainName(const std::string& domain, std::vector<std::string>& ips);

    }
}