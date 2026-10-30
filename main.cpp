#include "WindowsNetworkConfig.h"

#include <exception>
#include <iostream>
#include <string>
#include <vector>

// Examples (elevated console):
//   network_rules.exe add 192.0.2.10
//   network_rules.exe delete
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcerr << L"Usage:\n"
                   << L"  network_rules.exe add <destination-IPv4>\n"
                   << L"  network_rules.exe delete\n";
        return 2;
    }

    const std::wstring command = argv[1];
    const netconfig::PortProxyV4ToV4 forwarding{
        L"0.0.0.0", 8180, argc >= 3 ? argv[2] : L"", 8080
    };
    const netconfig::InboundTcpFirewallRule firewall{L"proxy forward", 8180};
    auto config = netconfig::CreateWindowsNetworkConfiguration();

    try {
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

        std::wcerr << L"Usage: network_rules.exe add <destination-IPv4> | delete\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Configuration error: " << error.what() << '\n';
        return 1;
    }
}
