use std::net::Ipv4Addr;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProxy {
    pub listen_address: Ipv4Addr,
    pub listen_port: u16,
    pub connect_address: Ipv4Addr,
    pub connect_port: u16,
}
#[derive(Debug, Default)]
pub struct FirewallRule {
    pub name: String,
    pub enabled: bool,
    pub direction: i32,
    pub action: i32,
    pub protocol: i32,
    pub local_addresses: String,
    pub remote_addresses: String,
    pub local_ports: String,
    pub remote_ports: String,
    pub profiles: i32,
    pub application: String,
    pub service: String,
    pub icmp_types_and_codes: String,
}
pub trait NetworkConfiguration {
    fn list_portproxies(&mut self) -> Result<Vec<PortProxy>>;
    fn list_firewall(&mut self) -> Result<Vec<FirewallRule>>;
    fn add_portproxy(&mut self, rule: &PortProxy) -> Result<()>;
    fn delete_portproxy(&mut self) -> Result<()>;
    fn add_firewall(&mut self) -> Result<()>;
    fn delete_firewall(&mut self) -> Result<()>;
}
pub fn endpoint(value: &str) -> Result<(Ipv4Addr, u16)> {
    let (address, port) = value.split_once('/').ok_or("invalid endpoint")?;
    let address = if address == "*" { "0.0.0.0" } else { address };
    let address = address.parse().map_err(|_| "invalid IPv4 address")?;
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid port".into());
    }
    let port = port.parse::<u16>().map_err(|_| "invalid port")?;
    if port == 0 {
        return Err("invalid port".into());
    }
    Ok((address, port))
}
