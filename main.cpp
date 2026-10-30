#include "WindowsNetworkConfig.h"

#include <exception>
#include <iostream>
#include <iomanip>
#include <locale>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void Usage() {
    std::wcerr << L"Usage:\n"
               << L"  network_rules.exe add <destination-IPv4>\n"
               << L"  network_rules.exe delete\n"
               << L"  network_rules.exe list <portproxy|firewall>\n";
}

std::wstring Display(const std::wstring& value) {
    return value.empty() ? L"N/A" : value;
}

std::wstring Protocol(long protocol) {
    switch (protocol) {
    case 1: return L"ICMPv4";
    case 6: return L"TCP";
    case 17: return L"UDP";
    case 58: return L"ICMPv6";
    case 256: return L"Any";
    default: return std::to_wstring(protocol);
    }
}

std::wstring Profiles(long profiles) {
    if (profiles == 0x7fffffff) return L"All";
    std::wstring result;
    auto add = [&result](const wchar_t* name) {
        if (!result.empty()) result += L", ";
        result += name;
    };
    if (profiles & 1) add(L"Domain");
    if (profiles & 2) add(L"Private");
    if (profiles & 4) add(L"Public");
    if (profiles & ~7L) add(std::to_wstring(profiles & ~7L).c_str());
    return result.empty() ? L"N/A" : result;
}

void ShowPortProxies(const std::vector<netconfig::PortProxyV4ToV4>& rules) {
    if (rules.empty()) { std::wcout << L"No rules found.\n"; return; }
    std::wcout << std::left << std::setw(20) << L"Listen address"
               << std::setw(14) << L"Listen port" << std::setw(20) << L"Destination address"
               << L"Destination port\n";
    for (const auto& rule : rules)
        std::wcout << std::left << std::setw(20) << rule.listen_address
                   << std::setw(14) << rule.listen_port << std::setw(20) << rule.connect_address
                   << rule.connect_port << L'\n';
}

void ShowFirewallRules(const std::vector<netconfig::FirewallRuleInfo>& rules) {
    if (rules.empty()) { std::wcout << L"No rules found.\n"; return; }
    for (const auto& rule : rules) {
        std::wcout << L"Name: " << Display(rule.name)
                   << L"\nEnabled: " << (rule.enabled ? L"Yes" : L"No")
                   << L"\nDirection: " << (rule.direction == 1 ? L"In" : rule.direction == 2 ? L"Out" : std::to_wstring(rule.direction))
                   << L"\nAction: " << (rule.action == 1 ? L"Allow" : rule.action == 0 ? L"Block" : std::to_wstring(rule.action))
                   << L"\nProtocol: " << Protocol(rule.protocol)
                   << L"\nLocal addresses: " << Display(rule.local_addresses)
                   << L"\nRemote addresses: " << Display(rule.remote_addresses)
                   << L"\nLocal ports: " << Display(rule.local_ports)
                   << L"\nRemote ports: " << Display(rule.remote_ports)
                   << L"\nProfiles: " << Profiles(rule.profiles)
                   << L"\nApplication: " << Display(rule.application)
                   << L"\nService: " << Display(rule.service)
                   << L"\nICMP types and codes: " << Display(rule.icmp_types_and_codes)
                   << L"\n\n";
    }
}
} // namespace

// Examples (elevated console):
//   network_rules.exe add 192.0.2.10
//   network_rules.exe delete
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        Usage();
        return 2;
    }

    const std::wstring command = argv[1];
    if (!((command == L"add" && argc == 3) ||
          (command == L"delete" && argc == 2) ||
          (command == L"list" && argc == 3 &&
           (std::wstring(argv[2]) == L"portproxy" || std::wstring(argv[2]) == L"firewall")))) {
        Usage();
        return 2;
    }
    const netconfig::PortProxyV4ToV4 forwarding{
        L"0.0.0.0", 8180, argc >= 3 ? argv[2] : L"", 8080
    };
    const netconfig::InboundTcpFirewallRule firewall{L"proxy forward", 8180};
    auto config = netconfig::CreateWindowsNetworkConfiguration();

    try {
        if (command == L"list") {
            // Use the user's locale for wide output, including non-ASCII rule names.
            try { std::wcout.imbue(std::locale("")); } catch (const std::runtime_error&) {}
            if (std::wstring(argv[2]) == L"portproxy") ShowPortProxies(config->ListPortProxies());
            else ShowFirewallRules(config->ListFirewallRules());
            return 0;
        }
        if (command == L"add" && argc == 3) {
            // netsh interface portproxy add v4tov4 listenport=8180
            //   connectaddress=<destination-IPv4> connectport=8080
            config->AddPortProxy(forwarding);
            std::wcout << L"PortProxy added.\n";

            try {
                // netsh advfirewall firewall add rule name="proxy forward"
                //   dir=in action=allow protocol=TCP localport=8180
                config->AddInboundTcpFirewallRule(firewall);
                std::wcout << L"Firewall rule added.\n";
            } catch (...) {
                // Avoid leaving a newly exposed listener if firewall setup fails.
                const std::exception_ptr original = std::current_exception();
                try {
                    config->DeletePortProxy(forwarding.listen_address,
                                            forwarding.listen_port);
                    std::wcerr << L"Rolled back PortProxy after firewall failure.\n";
                } catch (const std::exception& rollback_error) {
                    std::cerr << "PortProxy rollback ALSO failed: "
                              << rollback_error.what() << '\n';
                }
                std::rethrow_exception(original);
            }
            return 0;
        }

        if (command == L"delete" && argc == 2) {
            // Attempt both removals independently, even if the first fails.
            std::vector<std::string> errors;
            try {
                // netsh interface portproxy delete v4tov4
                //   listenport=8180 listenaddress=0.0.0.0
                config->DeletePortProxy(L"0.0.0.0", 8180);
                std::wcout << L"PortProxy deleted.\n";
            } catch (const std::exception& error) {
                errors.push_back(std::string("PortProxy: ") + error.what());
            }

            try {
                // netsh advfirewall firewall delete rule name="proxy forward"
                config->DeleteFirewallRule(firewall.name);
                std::wcout << L"Firewall rule deleted.\n";
            } catch (const std::exception& error) {
                errors.push_back(std::string("Firewall: ") + error.what());
            }
            for (const auto& error : errors) std::cerr << error << '\n';
            return errors.empty() ? 0 : 1;
        }

        Usage();
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Configuration error: " << error.what() << '\n';
        return 1;
    }
}
