use crate::model::{FirewallRule, NetworkConfiguration, PortProxy};
use std::net::Ipv4Addr;

pub const USAGE: &str = "Usage:\n  network_rules.exe add <destination-IPv4>\n  network_rules.exe delete\n  network_rules.exe list <portproxy|firewall>\n";
#[derive(Debug, PartialEq)]
pub enum Command {
    Add(Ipv4Addr),
    Delete,
    ListPortproxy,
    ListFirewall,
}
pub fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [cmd, address] if cmd == "add" => address
            .parse()
            .map(Command::Add)
            .map_err(|_| "An IPv4 address in dotted-decimal form is required".into()),
        [cmd] if cmd == "delete" => Ok(Command::Delete),
        [cmd, target] if cmd == "list" && target == "portproxy" => Ok(Command::ListPortproxy),
        [cmd, target] if cmd == "list" && target == "firewall" => Ok(Command::ListFirewall),
        _ => Err(USAGE.into()),
    }
}
fn display(s: &str) -> &str {
    if s.is_empty() {
        "N/A"
    } else {
        s
    }
}
fn profiles(p: i32) -> String {
    if p == i32::MAX {
        return "All".into();
    }
    let mut parts = Vec::new();
    for (bit, name) in [(1, "Domain"), (2, "Private"), (4, "Public")] {
        if p & bit != 0 {
            parts.push(name.to_string());
        }
    }
    if p & !7 != 0 {
        parts.push((p & !7).to_string());
    }
    if parts.is_empty() {
        "N/A".into()
    } else {
        parts.join(", ")
    }
}
pub fn portproxies(rules: &[PortProxy]) -> String {
    if rules.is_empty() {
        return "No rules found.\n".into();
    }
    let mut out = format!(
        "{:<20}{:<14}{:<20}Destination port\n",
        "Listen address", "Listen port", "Destination address"
    );
    for r in rules {
        out.push_str(&format!(
            "{:<20}{:<14}{:<20}{}\n",
            r.listen_address.to_string(),
            r.listen_port,
            r.connect_address.to_string(),
            r.connect_port
        ));
    }
    out
}
pub fn firewall(rules: &[FirewallRule]) -> String {
    if rules.is_empty() {
        return "No rules found.\n".into();
    }
    let mut out = String::new();
    for r in rules {
        let direction = match r.direction {
            1 => "In".into(),
            2 => "Out".into(),
            n => n.to_string(),
        };
        let action = match r.action {
            1 => "Allow".into(),
            0 => "Block".into(),
            n => n.to_string(),
        };
        let protocol = match r.protocol {
            1 => "ICMPv4".into(),
            6 => "TCP".into(),
            17 => "UDP".into(),
            58 => "ICMPv6".into(),
            256 => "Any".into(),
            n => n.to_string(),
        };
        out.push_str(&format!("Name: {}\nEnabled: {}\nDirection: {}\nAction: {}\nProtocol: {}\nLocal addresses: {}\nRemote addresses: {}\nLocal ports: {}\nRemote ports: {}\nProfiles: {}\nApplication: {}\nService: {}\nICMP types and codes: {}\n\n", display(&r.name), if r.enabled { "Yes" } else { "No" }, direction, action, protocol, display(&r.local_addresses), display(&r.remote_addresses), display(&r.local_ports), display(&r.remote_ports), profiles(r.profiles), display(&r.application), display(&r.service), display(&r.icmp_types_and_codes)));
    }
    out
}
pub fn execute(config: &mut impl NetworkConfiguration, command: Command) -> (i32, String, String) {
    let mut out = String::new();
    let mut err = String::new();
    let result = match command {
        Command::ListPortproxy => config
            .list_portproxies()
            .map(|rules| out.push_str(&portproxies(&rules))),
        Command::ListFirewall => config
            .list_firewall()
            .map(|rules| out.push_str(&firewall(&rules))),
        Command::Add(address) => {
            let rule = PortProxy {
                listen_address: Ipv4Addr::UNSPECIFIED,
                listen_port: 8180,
                connect_address: address,
                connect_port: 8080,
            };
            config.add_portproxy(&rule).and_then(|()| {
                out.push_str("PortProxy added.\n");
                match config.add_firewall() {
                    Ok(()) => {
                        out.push_str("Firewall rule added.\n");
                        Ok(())
                    }
                    Err(e) => {
                        match config.delete_portproxy() {
                            Ok(()) => {
                                err.push_str("Rolled back PortProxy after firewall failure.\n")
                            }
                            Err(e) => {
                                err.push_str(&format!("PortProxy rollback ALSO failed: {e}\n"))
                            }
                        };
                        Err(e)
                    }
                }
            })
        }
        Command::Delete => {
            let mut failed = false;
            for (name, result) in [
                ("PortProxy", config.delete_portproxy()),
                ("Firewall", config.delete_firewall()),
            ] {
                match result {
                    Ok(()) => out.push_str(&format!(
                        "{name} {}.\n",
                        if name == "Firewall" {
                            "rule deleted"
                        } else {
                            "deleted"
                        }
                    )),
                    Err(e) => {
                        failed = true;
                        err.push_str(&format!("{name}: {e}\n"));
                    }
                }
            }
            return (if failed { 1 } else { 0 }, out, err);
        }
    };
    if let Err(e) = result {
        err.push_str(&format!("Configuration error: {e}\n"));
        (1, out, err)
    } else {
        (0, out, err)
    }
}
