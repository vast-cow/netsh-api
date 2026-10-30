# Windows API Version: portproxy / Firewall Configuration (C++17)

This implementation performs operations equivalent to the following without invoking `netsh.exe`.

```cmd
netsh interface portproxy add v4tov4 listenport=8180 connectaddress=x.x.x.x connectport=8080
netsh advfirewall firewall add rule name="proxy forward" dir=in action=allow protocol=TCP localport=8180
netsh interface portproxy delete v4tov4 listenport=8180 listenaddress=0.0.0.0
netsh advfirewall firewall delete rule name="proxy forward"
```

## Structure

- `WindowsNetworkConfig.h`: `INetworkConfiguration` abstract interface and configuration model
- `WindowsNetworkConfig.cpp`: Implementation using Win32 Registry API, SCM API, and Windows Firewall COM API
- `main.cpp`: Example of executing `add` and `delete`
- `CMakeLists.txt`: Build definition for Windows / MSVC

## Build

In Visual Studio's Developer PowerShell, execute the following:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Or directly from the x64 Native Tools Command Prompt for VS:

```cmd
cl /nologo /std:c++17 /EHsc /W4 /DUNICODE /D_UNICODE main.cpp WindowsNetworkConfig.cpp /link advapi32.lib ole32.lib oleaut32.lib ws2_32.lib
```

## Execution

In a terminal with **administrator privileges**, replace the destination with the actual IPv4 address.

```powershell
.\build\Release\network_rules.exe add 192.0.2.10
.\build\Release\network_rules.exe delete
```

`192.0.2.10` is an example IP address for documentation purposes.

## Verifying the Configuration Results

```cmd
netsh interface portproxy show v4tov4
netsh advfirewall firewall show rule name="proxy forward"
netstat -ano | findstr :8180
```

## Important Notes

- The registry format for PortProxy is not a publicly documented management API; it is an implementation-dependent format determined by ProcMon. Compatibility after Windows updates is not guaranteed.
- Modifies `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` using `RegSetValueExW` / `RegDeleteValueW` and sends `SERVICE_CONTROL_PARAMCHANGE` to `iphlpsvc`.
- Normalizes `listenaddress=0.0.0.0` as the value name `*/8180`. During deletion, it also treats the older manual configuration `0.0.0.0/8180` as a fallback.
- `INetFwRules::Add` may overwrite rules with the same name; therefore, this implementation throws an exception if an existing name is detected using `Item`. Consequently, it does not behave identically to `netsh add` if an existing rule is present.
- IPv4 addresses are supported only in numerical representation (`netsh`'s support for hostnames is not supported). The port range is 1 to 65535.
- There is no complete transaction spanning PortProxy and Firewall. If adding the Firewall rule fails, the PortProxy created immediately before is deleted on a best-effort basis. Deletion is attempted independently for both.
- The success of `ControlService` indicates that the notification to the service was successful, but does not guarantee connectivity. `iphlpsvc` must be running, and the destination must be reachable.
- The rule allows inbound TCP traffic on port 8180 for all profiles and listens on all IPv4 interfaces. This makes it accessible from outside, so consider restricting the source address in a production environment.
- This sample has not been verified by building and running on Windows.

## References

- [Microsoft: netsh interface portproxy](https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-interface-portproxy)
- [Microsoft: ControlService](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-controlservice)
- [Microsoft: INetFwRules::Add](https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-inetfwrules-add)
- [Microsoft: INetFwRules::Remove](https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-inetfwrules-remove)
- [Microsoft: Windows Firewall C++ sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/windowsfirewall)
- [Independent reverse engineering of PortProxy / iphlpsvc](https://adepts.of0x.cc/netsh-portproxy-code/)
