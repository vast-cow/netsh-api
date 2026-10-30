#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace netconfig {

// Only IPv4-to-IPv4 TCP forwarding is supported, matching portproxy v4tov4.
struct PortProxyV4ToV4 {
    std::wstring listen_address = L"0.0.0.0";
    std::uint16_t listen_port = 0;
    std::wstring connect_address;
    std::uint16_t connect_port = 0;
};

struct InboundTcpFirewallRule {
    std::wstring name;
    std::uint16_t local_port = 0;
};

// This abstraction does not execute netsh.exe or PowerShell.
// Methods throw std::exception-derived errors on failure.
class INetworkConfiguration {
public:
    virtual ~INetworkConfiguration() = default;

    virtual void AddPortProxy(const PortProxyV4ToV4& rule) = 0;
    virtual void DeletePortProxy(const std::wstring& listen_address,
                                 std::uint16_t listen_port) = 0;
    virtual void AddInboundTcpFirewallRule(const InboundTcpFirewallRule& rule) = 0;
    virtual void DeleteFirewallRule(const std::wstring& name) = 0;
};

std::unique_ptr<INetworkConfiguration> CreateWindowsNetworkConfiguration();

} // namespace netconfig
