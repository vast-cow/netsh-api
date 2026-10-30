// Windows-only implementation. Build with MSVC and the Windows SDK.
#include "WindowsNetworkConfig.h"

#ifndef _WIN32
#error This implementation requires Windows.
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include <netfw.h>
#include <wrl/client.h>

#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace netconfig {
namespace {

constexpr wchar_t kPortProxyKey[] =
    L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp";

[[noreturn]] void ThrowWin32(const char* operation, LONG error) {
    std::ostringstream message;
    message << operation << " failed (Win32 code " << error << ")";
    throw std::runtime_error(message.str());
}

void CheckWin32(LONG status, const char* operation) {
    if (status != ERROR_SUCCESS) {
        ThrowWin32(operation, status);
    }
}

void CheckHresult(HRESULT hr, const char* operation) {
    if (FAILED(hr)) {
        std::ostringstream message;
        message << operation << " failed (HRESULT 0x" << std::hex
                << std::uppercase << std::setw(8) << std::setfill('0')
                << static_cast<unsigned long>(hr) << ")";
        throw std::runtime_error(message.str());
    }
}

class RegistryKey final {
public:
    explicit RegistryKey(HKEY handle) noexcept : handle_(handle) {}
    ~RegistryKey() {
        if (handle_) RegCloseKey(handle_);
    }
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;

    HKEY Get() const noexcept { return handle_; }

private:
    HKEY handle_ = nullptr;
};

class ServiceHandle final {
public:
    explicit ServiceHandle(SC_HANDLE handle) noexcept : handle_(handle) {}
    ~ServiceHandle() {
        if (handle_) CloseServiceHandle(handle_);
    }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    SC_HANDLE Get() const noexcept { return handle_; }

private:
    SC_HANDLE handle_ = nullptr;
};

class ComApartment final {
public:
    ComApartment() {
        result_ = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        // If this thread is already initialized as MTA, continue using that
        // existing apartment. RPC_E_CHANGED_MODE does not increment the COM
        // initialization count, so it must not be paired with CoUninitialize.
        if (result_ != RPC_E_CHANGED_MODE) {
            CheckHresult(result_, "CoInitializeEx");
        }
    }
    ~ComApartment() {
        if (SUCCEEDED(result_)) CoUninitialize();
    }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;

private:
    HRESULT result_ = E_FAIL;
};

class OwnedBstr final {
public:
    explicit OwnedBstr(const std::wstring& text)
        : bstr_(SysAllocStringLen(text.data(), static_cast<UINT>(text.size()))) {
        if (!bstr_) throw std::bad_alloc();
    }
    ~OwnedBstr() { SysFreeString(bstr_); }
    OwnedBstr(const OwnedBstr&) = delete;
    OwnedBstr& operator=(const OwnedBstr&) = delete;

    BSTR Get() const noexcept { return bstr_; }

private:
    BSTR bstr_ = nullptr;
};

void RequirePort(std::uint16_t port) {
    if (port == 0) {
        throw std::invalid_argument("TCP ports must be in the range 1-65535");
    }
}

void RequireIPv4(const std::wstring& address) {
    IN_ADDR parsed{};
    if (InetPtonW(AF_INET, address.c_str(), &parsed) != 1) {
        throw std::invalid_argument("An IPv4 address in dotted-decimal form is required");
    }
}

std::wstring MakeRegistryValueName(const std::wstring& listen_address,
                                   std::uint16_t port) {
    RequirePort(port);
    // This is the encoding observed in the supplied ProcMon CSVs.
    const std::wstring normalized =
        (listen_address == L"0.0.0.0" || listen_address == L"*")
            ? L"*"
            : listen_address;
    if (normalized != L"*") RequireIPv4(normalized);
    return normalized + L"/" + std::to_wstring(port);
}

void NotifyIpHelper() {
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.Get()) ThrowWin32("OpenSCManagerW", GetLastError());

    ServiceHandle service(OpenServiceW(
        manager.Get(), L"iphlpsvc", SERVICE_PAUSE_CONTINUE));
    if (!service.Get()) ThrowWin32("OpenServiceW(iphlpsvc)", GetLastError());

    SERVICE_STATUS status{};
    if (!ControlService(service.Get(), SERVICE_CONTROL_PARAMCHANGE, &status)) {
        ThrowWin32("ControlService(SERVICE_CONTROL_PARAMCHANGE)", GetLastError());
    }
    // ControlService returning success means that the control was delivered;
    // it does not guarantee that the destination is reachable or listening.
}

Microsoft::WRL::ComPtr<INetFwRules> GetFirewallRules() {
    using Microsoft::WRL::ComPtr;

    ComPtr<INetFwPolicy2> policy;
    CheckHresult(CoCreateInstance(
        __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(policy.GetAddressOf())),
        "CoCreateInstance(NetFwPolicy2)");

    ComPtr<INetFwRules> rules;
    CheckHresult(policy->get_Rules(rules.GetAddressOf()), "INetFwPolicy2::get_Rules");
    return rules;
}

class WindowsNetworkConfiguration final : public INetworkConfiguration {
public:
    void AddPortProxy(const PortProxyV4ToV4& rule) override {
        RequirePort(rule.listen_port);
        RequirePort(rule.connect_port);
        RequireIPv4(rule.connect_address);

        const std::wstring value_name =
            MakeRegistryValueName(rule.listen_address, rule.listen_port);
        const std::wstring value_data =
            rule.connect_address + L"/" + std::to_wstring(rule.connect_port);

        HKEY raw_key = nullptr;
        CheckWin32(RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, kPortProxyKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &raw_key, nullptr),
            "RegCreateKeyExW(PortProxy)");
        RegistryKey key(raw_key);

        // Add must not silently replace an existing forwarding configuration.
        DWORD bytes = 0;
        const LONG lookup = RegQueryValueExW(
            key.Get(), value_name.c_str(), nullptr, nullptr, nullptr, &bytes);
        if (lookup == ERROR_SUCCESS) {
            throw std::runtime_error("A portproxy rule for this listener already exists");
        }
        if (lookup != ERROR_FILE_NOT_FOUND) {
            ThrowWin32("RegQueryValueExW(PortProxy)", lookup);
        }

        CheckWin32(RegSetValueExW(
            key.Get(), value_name.c_str(), 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value_data.c_str()),
            static_cast<DWORD>((value_data.size() + 1) * sizeof(wchar_t))),
            "RegSetValueExW(PortProxy)");

        // If notification fails, remove the newly created entry; the rule may
        // nevertheless have been observed by the service. Report the failure.
        try {
            NotifyIpHelper();
        } catch (...) {
            RegDeleteValueW(key.Get(), value_name.c_str()); // best effort
            throw;
        }
    }

    void DeletePortProxy(const std::wstring& listen_address,
                         std::uint16_t listen_port) override {
        const std::wstring value_name =
            MakeRegistryValueName(listen_address, listen_port);

        HKEY raw_key = nullptr;
        CheckWin32(RegOpenKeyExW(
            HKEY_LOCAL_MACHINE, kPortProxyKey, 0, KEY_SET_VALUE, &raw_key),
            "RegOpenKeyExW(PortProxy)");
        RegistryKey key(raw_key);

        LONG result = RegDeleteValueW(key.Get(), value_name.c_str());
        // Older/manual entries can use "0.0.0.0/PORT" instead of "*/PORT".
        if (result == ERROR_FILE_NOT_FOUND &&
            (listen_address == L"0.0.0.0" || listen_address == L"*")) {
            const std::wstring alternative =
                L"0.0.0.0/" + std::to_wstring(listen_port);
            result = RegDeleteValueW(key.Get(), alternative.c_str());
        }
        CheckWin32(result, "RegDeleteValueW(PortProxy)");
        NotifyIpHelper();
    }

    void AddInboundTcpFirewallRule(const InboundTcpFirewallRule& rule) override {
        RequirePort(rule.local_port);
        if (rule.name.empty()) throw std::invalid_argument("Firewall rule name is empty");

        ComApartment com;
        const auto rules = GetFirewallRules();
        const OwnedBstr name(rule.name);

        // Protect an existing rule from INetFwRules::Add overwriting it.
        Microsoft::WRL::ComPtr<INetFwRule> existing;
        if (SUCCEEDED(rules->Item(name.Get(), existing.GetAddressOf()))) {
            throw std::runtime_error("A firewall rule with this name already exists");
        }

        Microsoft::WRL::ComPtr<INetFwRule> fw_rule;
        CheckHresult(CoCreateInstance(
            __uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(INetFwRule),
            reinterpret_cast<void**>(fw_rule.GetAddressOf())),
            "CoCreateInstance(NetFwRule)");

        const OwnedBstr port(std::to_wstring(rule.local_port));
        CheckHresult(fw_rule->put_Name(name.Get()), "INetFwRule::put_Name");
        CheckHresult(fw_rule->put_Direction(NET_FW_RULE_DIR_IN),
                     "INetFwRule::put_Direction");
        // Protocol MUST be assigned before LocalPorts.
        CheckHresult(fw_rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP),
                     "INetFwRule::put_Protocol");
        CheckHresult(fw_rule->put_LocalPorts(port.Get()),
                     "INetFwRule::put_LocalPorts");
        CheckHresult(fw_rule->put_Action(NET_FW_ACTION_ALLOW),
                     "INetFwRule::put_Action");
        CheckHresult(fw_rule->put_Profiles(NET_FW_PROFILE2_ALL),
                     "INetFwRule::put_Profiles");
        CheckHresult(fw_rule->put_Enabled(VARIANT_TRUE),
                     "INetFwRule::put_Enabled");
        CheckHresult(rules->Add(fw_rule.Get()), "INetFwRules::Add");
    }

    void DeleteFirewallRule(const std::wstring& name) override {
        if (name.empty()) throw std::invalid_argument("Firewall rule name is empty");
        ComApartment com;
        const auto rules = GetFirewallRules();
        const OwnedBstr bstr_name(name);
        CheckHresult(rules->Remove(bstr_name.Get()), "INetFwRules::Remove");
    }
};

} // namespace

std::unique_ptr<INetworkConfiguration> CreateWindowsNetworkConfiguration() {
    return std::make_unique<WindowsNetworkConfiguration>();
}

} // namespace netconfig
