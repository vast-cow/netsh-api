// Windows-only implementation. Build with MSVC and the Windows SDK.
#include "WindowsNetworkConfig.h"

#ifndef _WIN32
#error This implementation requires Windows.
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include <netfw.h>
#include <wrl/client.h>

#include <algorithm>
#include <iomanip>
#include <vector>
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

std::string Utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!size) return "<unrepresentable value name>";
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

void ParseEndpoint(const std::wstring& endpoint, std::wstring& address,
                   std::uint16_t& port) {
    if (endpoint.find(L'\0') != std::wstring::npos)
        throw std::invalid_argument("invalid endpoint");
    const auto slash = endpoint.find(L'/');
    if (slash == std::wstring::npos || slash == 0 || slash + 1 == endpoint.size() ||
        endpoint.find(L'/', slash + 1) != std::wstring::npos) {
        throw std::invalid_argument("invalid endpoint");
    }
    address = endpoint.substr(0, slash);
    if (address == L"*") address = L"0.0.0.0";
    RequireIPv4(address);
    unsigned int number = 0;
    for (const wchar_t c : endpoint.substr(slash + 1)) {
        if (c < L'0' || c > L'9') throw std::invalid_argument("invalid port");
        number = number * 10 + (c - L'0');
        if (number > 65535) throw std::invalid_argument("invalid port");
    }
    if (!number) throw std::invalid_argument("invalid port");
    port = static_cast<std::uint16_t>(number);
}

class Variant final {
public:
    Variant() { VariantInit(&value); }
    ~Variant() { VariantClear(&value); }
    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;
    VARIANT value;
};

std::wstring ReadRuleString(INetFwRule* rule,
                            HRESULT (STDMETHODCALLTYPE INetFwRule::*getter)(BSTR*),
                            const char* operation) {
    BSTR value = nullptr;
    const HRESULT hr = (rule->*getter)(&value);
    // Some implementations may return a BSTR even on failure.
    std::unique_ptr<wchar_t, decltype(&SysFreeString)> owned(value, &SysFreeString);
    CheckHresult(hr, operation);
    return value ? std::wstring(value, SysStringLen(value)) : std::wstring();
}

class WindowsNetworkConfiguration final : public INetworkConfiguration {
public:
    std::vector<PortProxyV4ToV4> ListPortProxies() override {
        HKEY raw_key = nullptr;
        const LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPortProxyKey, 0,
                                          KEY_QUERY_VALUE, &raw_key);
        if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) return {};
        CheckWin32(opened, "RegOpenKeyExW(PortProxy)");
        RegistryKey key(raw_key);
        std::vector<PortProxyV4ToV4> result;
        std::vector<wchar_t> name(256), data(256);
        for (DWORD index = 0;; ++index) {
            DWORD name_length, data_bytes, type;
            LONG status;
            for (;;) {
                name_length = static_cast<DWORD>(name.size());
                data_bytes = static_cast<DWORD>(data.size() * sizeof(wchar_t));
                status = RegEnumValueW(key.Get(), index, name.data(), &name_length,
                                       nullptr, &type, reinterpret_cast<BYTE*>(data.data()),
                                       &data_bytes);
                if (status != ERROR_MORE_DATA) break;
                // RegEnumValueW may not report the required name size on overflow.
                name.resize(std::max(name.size() * 2, static_cast<size_t>(name_length) + 1));
                data.resize(std::max(data.size() * 2,
                    (static_cast<size_t>(data_bytes) + sizeof(wchar_t) - 1) / sizeof(wchar_t)));
            }
            if (status == ERROR_NO_MORE_ITEMS) break;
            CheckWin32(status, "RegEnumValueW(PortProxy)");
            const std::wstring value_name(name.data(), name_length);
            try {
                if (type != REG_SZ || data_bytes < sizeof(wchar_t) ||
                    data_bytes % sizeof(wchar_t) != 0 ||
                    data[data_bytes / sizeof(wchar_t) - 1] != L'\0') {
                    throw std::invalid_argument("invalid registry value type or data");
                }
                const std::wstring value_data(data.data(), data_bytes / sizeof(wchar_t) - 1);
                PortProxyV4ToV4 rule;
                ParseEndpoint(value_name, rule.listen_address, rule.listen_port);
                ParseEndpoint(value_data, rule.connect_address, rule.connect_port);
                result.push_back(std::move(rule));
            } catch (const std::invalid_argument& error) {
                throw std::runtime_error("Invalid PortProxy value '" + Utf8(value_name) +
                                         "': " + error.what());
            }
        }
        return result;
    }

    std::vector<FirewallRuleInfo> ListFirewallRules() override {
        ComApartment com;
        const auto rules = GetFirewallRules();
        Microsoft::WRL::ComPtr<IUnknown> unknown;
        CheckHresult(rules->get__NewEnum(unknown.GetAddressOf()), "INetFwRules::get__NewEnum");
        Microsoft::WRL::ComPtr<IEnumVARIANT> enumerator;
        CheckHresult(unknown.As(&enumerator), "QueryInterface(IEnumVARIANT)");
        std::vector<FirewallRuleInfo> result;
        for (;;) {
            Variant item;
            ULONG fetched = 0;
            const HRESULT hr = enumerator->Next(1, &item.value, &fetched);
            CheckHresult(hr, "IEnumVARIANT::Next");
            if (fetched == 0) break;
            if (item.value.vt != VT_DISPATCH || !item.value.pdispVal)
                throw std::runtime_error("Invalid firewall enumeration item");
            Microsoft::WRL::ComPtr<INetFwRule> rule;
            CheckHresult(item.value.pdispVal->QueryInterface(IID_PPV_ARGS(rule.GetAddressOf())),
                         "QueryInterface(INetFwRule)");
            FirewallRuleInfo info;
            info.name = ReadRuleString(rule.Get(), &INetFwRule::get_Name, "INetFwRule::get_Name");
            VARIANT_BOOL enabled;
            CheckHresult(rule->get_Enabled(&enabled), "INetFwRule::get_Enabled");
            info.enabled = enabled != VARIANT_FALSE;
            NET_FW_RULE_DIRECTION direction;
            NET_FW_ACTION action;
            CheckHresult(rule->get_Direction(&direction), "INetFwRule::get_Direction");
            CheckHresult(rule->get_Action(&action), "INetFwRule::get_Action");
            info.direction = direction;
            info.action = action;
            CheckHresult(rule->get_Protocol(&info.protocol), "INetFwRule::get_Protocol");
            CheckHresult(rule->get_Profiles(&info.profiles), "INetFwRule::get_Profiles");
            info.local_addresses = ReadRuleString(rule.Get(), &INetFwRule::get_LocalAddresses, "INetFwRule::get_LocalAddresses");
            info.remote_addresses = ReadRuleString(rule.Get(), &INetFwRule::get_RemoteAddresses, "INetFwRule::get_RemoteAddresses");
            info.application = ReadRuleString(rule.Get(), &INetFwRule::get_ApplicationName, "INetFwRule::get_ApplicationName");
            info.service = ReadRuleString(rule.Get(), &INetFwRule::get_ServiceName, "INetFwRule::get_ServiceName");
            if (info.protocol == NET_FW_IP_PROTOCOL_TCP || info.protocol == NET_FW_IP_PROTOCOL_UDP) {
                info.local_ports = ReadRuleString(rule.Get(), &INetFwRule::get_LocalPorts, "INetFwRule::get_LocalPorts");
                info.remote_ports = ReadRuleString(rule.Get(), &INetFwRule::get_RemotePorts, "INetFwRule::get_RemotePorts");
            }
            if (info.protocol == 1 || info.protocol == 58)
                info.icmp_types_and_codes = ReadRuleString(rule.Get(), &INetFwRule::get_IcmpTypesAndCodes, "INetFwRule::get_IcmpTypesAndCodes");
            result.push_back(std::move(info));
        }
        return result;
    }

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
