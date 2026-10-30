mod cli;
mod model;
#[cfg(windows)]
mod windows;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse(&args) {
        Ok(command) => command,
        Err(error) => {
            if error == cli::USAGE {
                eprint!("{error}");
                std::process::exit(2);
            }
            eprintln!("Configuration error: {error}");
            std::process::exit(1);
        }
    };
    #[cfg(windows)]
    let (code, out, err) = cli::execute(&mut windows::WindowsNetworkConfiguration, command);
    #[cfg(not(windows))]
    let (code, out, err) = {
        let _ = command;
        (
            1,
            String::new(),
            "Execution on non-Windows is not supported.\n".to_string(),
        )
    };
    print!("{out}");
    eprint!("{err}");
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::{
        cli::{self, Command},
        model::*,
    };
    #[derive(Default)]
    struct Mock {
        calls: Vec<&'static str>,
        fail: Vec<&'static str>,
    }
    impl Mock {
        fn call(&mut self, name: &'static str) -> Result<()> {
            self.calls.push(name);
            if self.fail.contains(&name) {
                Err(format!("{name} failed"))
            } else {
                Ok(())
            }
        }
    }
    impl NetworkConfiguration for Mock {
        fn list_portproxies(&mut self) -> Result<Vec<PortProxy>> {
            self.call("list_portproxy")?;
            Ok(vec![])
        }
        fn list_firewall(&mut self) -> Result<Vec<FirewallRule>> {
            self.call("list_firewall")?;
            Ok(vec![])
        }
        fn add_portproxy(&mut self, _: &PortProxy) -> Result<()> {
            self.call("add_portproxy")
        }
        fn delete_portproxy(&mut self) -> Result<()> {
            self.call("delete_portproxy")
        }
        fn add_firewall(&mut self) -> Result<()> {
            self.call("add_firewall")
        }
        fn delete_firewall(&mut self) -> Result<()> {
            self.call("delete_firewall")
        }
    }
    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn arguments() {
        assert_eq!(
            cli::parse(&args(&["add", "192.0.2.1"])),
            Ok(Command::Add("192.0.2.1".parse().unwrap()))
        );
        for a in [
            &[][..],
            &["add"][..],
            &["add", "256.0.0.1"][..],
            &["delete", "extra"][..],
            &["list", "bad"][..],
        ] {
            assert!(cli::parse(&args(a)).is_err());
        }
        assert_eq!(
            cli::parse(&args(&["list", "firewall"])),
            Ok(Command::ListFirewall)
        );
    }
    #[test]
    fn endpoints() {
        assert_eq!(endpoint("*/1").unwrap(), ("0.0.0.0".parse().unwrap(), 1));
        assert_eq!(endpoint("255.255.255.255/65535").unwrap().1, 65535);
        for s in ["*/0", "*/65536", "*/-1", "*/1/2", "256.0.0.1/1", "*/1\0"] {
            assert!(endpoint(s).is_err(), "{s}");
        }
    }
    #[test]
    fn display() {
        assert_eq!(cli::portproxies(&[]), "No rules found.\n");
        let text = cli::firewall(&[FirewallRule {
            name: "日本語".into(),
            protocol: 6,
            direction: 1,
            action: 1,
            profiles: 5,
            ..Default::default()
        }]);
        for value in ["日本語", "TCP", "In", "Allow", "Domain, Public", "N/A"] {
            assert!(text.contains(value));
        }
        assert_eq!(cli::firewall(&[]), "No rules found.\n");
    }
    #[test]
    fn rollback() {
        let mut m = Mock {
            fail: vec!["add_firewall", "delete_portproxy"],
            ..Default::default()
        };
        let (code, _, err) = cli::execute(&mut m, Command::Add("192.0.2.1".parse().unwrap()));
        assert_eq!(code, 1);
        assert_eq!(
            m.calls,
            ["add_portproxy", "add_firewall", "delete_portproxy"]
        );
        assert!(err.contains("rollback ALSO failed"));
        assert!(err.contains("add_firewall failed"));
        let mut m = Mock {
            fail: vec!["add_portproxy"],
            ..Default::default()
        };
        cli::execute(&mut m, Command::Add("192.0.2.1".parse().unwrap()));
        assert_eq!(m.calls, ["add_portproxy"]);
    }
    #[test]
    fn deletion_aggregates_errors() {
        let mut m = Mock {
            fail: vec!["delete_portproxy", "delete_firewall"],
            ..Default::default()
        };
        let (code, _, err) = cli::execute(&mut m, Command::Delete);
        assert_eq!(code, 1);
        assert_eq!(m.calls, ["delete_portproxy", "delete_firewall"]);
        assert!(err.contains("PortProxy:"));
        assert!(err.contains("Firewall:"));
    }
}
