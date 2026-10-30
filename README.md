# Windows PortProxy and Firewall Configuration

`network_rules` configures IPv4 TCP forwarding and Windows Firewall directly through Windows APIs, without executing `netsh` or PowerShell. It listens on `0.0.0.0:8180`, forwards to port `8080` on the requested destination, and adds an inbound TCP firewall rule named `proxy forward` for all profiles.

## Build

Install Rust with the Windows x64 MSVC target and the Visual Studio C++ build tools and Windows SDK. From a Windows x64 MSVC terminal, run:

```powershell
cargo build --release
```

The executable is `target\release\network_rules.exe`. `Cargo.lock` pins dependencies; `target/` contains build output.

## Usage

Run from an administrator terminal, replacing the example IPv4 address with the actual destination:

```powershell
.\target\release\network_rules.exe add 192.0.2.10
.\target\release\network_rules.exe list portproxy
.\target\release\network_rules.exe list firewall
.\target\release\network_rules.exe delete
```

`list portproxy` reads IPv4-to-IPv4 TCP forwarding entries. `list firewall` reads all firewall rules, including disabled, outgoing, and identically named rules. Listing does not change configuration or notify services. An empty list is successful. Exit codes are 0 for success, 1 for an operation error, and 2 for invalid arguments. Execution on non-Windows systems is unsupported; pure logic tests can run there with `cargo test`.

## Behavior and verification

PortProxy uses `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` and notifies `iphlpsvc` with `SERVICE_CONTROL_PARAMCHANGE`. The registry representation is an undocumented implementation detail and may change in Windows. The wildcard listener is stored as `*/8180`; deletion falls back to the older `0.0.0.0/8180` form. Malformed registry entries cause listing to report an error.

Existing listener or firewall names are rejected. If adding the firewall rule fails, the newly added PortProxy entry is removed on a best-effort basis. Deletion attempts both operations independently. This is not a transaction; notification success does not guarantee reachability. `iphlpsvc` must be running and the destination must be reachable. The listener accepts traffic on all IPv4 interfaces and the firewall rule applies to all profiles.

On Windows, verify addition, both listings, deletion, and actual forwarding to the destination. These diagnostic commands can also help inspect the resulting configuration:

```cmd
netsh interface portproxy show v4tov4
netsh advfirewall firewall show rule name=all
netstat -ano | findstr :8180
```

Windows build and live forwarding verification have not been performed in the Linux development environment.
