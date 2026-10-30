use crate::model::{endpoint, FirewallRule, NetworkConfiguration, PortProxy, Result};
use windows::core::{IUnknown, Interface, BSTR, PCWSTR, PWSTR, VARIANT};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
    ERROR_SUCCESS, RPC_E_CHANGED_MODE, VARIANT_TRUE, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::WindowsFirewall::*;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Registry::*;
use windows::Win32::System::Services::*;

const KEY: &str = "SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp";
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn check(status: WIN32_ERROR, operation: &str) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{operation} failed (Win32 code {})", status.0))
    }
}
fn api<T>(result: windows::core::Result<T>, operation: &str) -> Result<T> {
    result.map_err(|e| format!("{operation} failed: {e}"))
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}
struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}
struct Apartment(bool);
impl Apartment {
    fn new() -> Result<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr == RPC_E_CHANGED_MODE {
            Ok(Self(false))
        } else {
            api(hr.ok(), "CoInitializeEx")?;
            Ok(Self(true))
        }
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() }
        }
    }
}
fn open_key(access: REG_SAM_FLAGS) -> std::result::Result<Key, WIN32_ERROR> {
    let mut key = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide(KEY).as_ptr()),
            0,
            access,
            &mut key,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(Key(key))
    } else {
        Err(status)
    }
}
fn notify() -> Result<()> {
    unsafe {
        let manager = Service(api(
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT),
            "OpenSCManagerW",
        )?);
        let service = Service(api(
            OpenServiceW(
                manager.0,
                PCWSTR(wide("iphlpsvc").as_ptr()),
                SERVICE_PAUSE_CONTINUE,
            ),
            "OpenServiceW(iphlpsvc)",
        )?);
        api(
            ControlService(
                service.0,
                SERVICE_CONTROL_PARAMCHANGE,
                &mut SERVICE_STATUS::default(),
            ),
            "ControlService(SERVICE_CONTROL_PARAMCHANGE)",
        )
    }
}
fn rules() -> Result<INetFwRules> {
    unsafe {
        let policy: INetFwPolicy2 = api(
            CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER),
            "CoCreateInstance(NetFwPolicy2)",
        )?;
        api(policy.Rules(), "INetFwPolicy2::Rules")
    }
}
pub struct WindowsNetworkConfiguration;
impl NetworkConfiguration for WindowsNetworkConfiguration {
    fn list_portproxies(&mut self) -> Result<Vec<PortProxy>> {
        let key = match open_key(KEY_QUERY_VALUE) {
            Ok(k) => k,
            Err(e) if e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND => return Ok(vec![]),
            Err(e) => {
                check(e, "RegOpenKeyExW(PortProxy)")?;
                unreachable!()
            }
        };
        let mut result = Vec::new();
        let mut name = vec![0u16; 256];
        let mut data = vec![0u8; 512];
        for index in 0.. {
            let (name_len, data_len, kind) = loop {
                let mut nl = name.len() as u32;
                let mut dl = data.len() as u32;
                let mut kind = 0;
                let status = unsafe {
                    RegEnumValueW(
                        key.0,
                        index,
                        PWSTR(name.as_mut_ptr()),
                        &mut nl,
                        None,
                        Some(&mut kind),
                        Some(data.as_mut_ptr()),
                        Some(&mut dl),
                    )
                };
                if status == ERROR_NO_MORE_ITEMS {
                    return Ok(result);
                }
                if status == ERROR_MORE_DATA {
                    name.resize((name.len() * 2).max(nl as usize + 1), 0);
                    data.resize((data.len() * 2).max(dl as usize), 0);
                    continue;
                }
                check(status, "RegEnumValueW(PortProxy)")?;
                break (nl as usize, dl as usize, kind);
            };
            let value_name = String::from_utf16(&name[..name_len])
                .map_err(|_| "Invalid UTF-16 PortProxy value name")?;
            let parse = || -> Result<PortProxy> {
                if kind != REG_SZ.0 || data_len < 2 || data_len % 2 != 0 {
                    return Err("invalid registry value type or data".into());
                }
                let chars: Vec<u16> = data[..data_len]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                if chars.last() != Some(&0) {
                    return Err("invalid registry value type or data".into());
                }
                let value =
                    String::from_utf16(&chars[..chars.len() - 1]).map_err(|_| "invalid UTF-16")?;
                let (listen_address, listen_port) = endpoint(&value_name)?;
                let (connect_address, connect_port) = endpoint(&value)?;
                Ok(PortProxy {
                    listen_address,
                    listen_port,
                    connect_address,
                    connect_port,
                })
            };
            result
                .push(parse().map_err(|e| format!("Invalid PortProxy value '{value_name}': {e}"))?);
        }
        unreachable!()
    }
    fn list_firewall(&mut self) -> Result<Vec<FirewallRule>> {
        let _com = Apartment::new()?;
        unsafe {
            let rules = rules()?;
            let enumerator: IEnumVARIANT = api(
                api(rules._NewEnum(), "INetFwRules::_NewEnum")?.cast(),
                "QueryInterface(IEnumVARIANT)",
            )?;
            let mut result = Vec::new();
            loop {
                let mut item = [VARIANT::default()];
                let mut fetched = 0;
                api(
                    enumerator.Next(&mut item, &mut fetched).ok(),
                    "IEnumVARIANT::Next",
                )?;
                if fetched == 0 {
                    break;
                }
                let raw = &item[0].as_raw().Anonymous.Anonymous;
                if raw.vt != 9 {
                    return Err("Invalid firewall enumeration item".into());
                }
                let ptr = raw.Anonymous.pdispVal;
                let unknown =
                    IUnknown::from_raw_borrowed(&ptr).ok_or("Invalid firewall enumeration item")?;
                let rule: INetFwRule = api(unknown.cast(), "QueryInterface(INetFwRule)")?;
                let protocol = api(rule.Protocol(), "INetFwRule::Protocol")?;
                let s = |r: windows::core::Result<BSTR>, op| api(r, op).map(|v| v.to_string());
                result.push(FirewallRule {
                    name: s(rule.Name(), "Name")?,
                    enabled: api(rule.Enabled(), "Enabled")?.as_bool(),
                    direction: api(rule.Direction(), "Direction")?.0,
                    action: api(rule.Action(), "Action")?.0,
                    protocol,
                    local_addresses: s(rule.LocalAddresses(), "LocalAddresses")?,
                    remote_addresses: s(rule.RemoteAddresses(), "RemoteAddresses")?,
                    local_ports: if protocol == 6 || protocol == 17 {
                        s(rule.LocalPorts(), "LocalPorts")?
                    } else {
                        String::new()
                    },
                    remote_ports: if protocol == 6 || protocol == 17 {
                        s(rule.RemotePorts(), "RemotePorts")?
                    } else {
                        String::new()
                    },
                    profiles: api(rule.Profiles(), "Profiles")?,
                    application: s(rule.ApplicationName(), "ApplicationName")?,
                    service: s(rule.ServiceName(), "ServiceName")?,
                    icmp_types_and_codes: if protocol == 1 || protocol == 58 {
                        s(rule.IcmpTypesAndCodes(), "IcmpTypesAndCodes")?
                    } else {
                        String::new()
                    },
                });
            }
            Ok(result)
        }
    }
    fn add_portproxy(&mut self, rule: &PortProxy) -> Result<()> {
        if rule.listen_port == 0 || rule.connect_port == 0 {
            return Err("TCP ports must be in the range 1-65535".into());
        }
        let name = format!(
            "{}/{}",
            if rule.listen_address.is_unspecified() {
                "*".into()
            } else {
                rule.listen_address.to_string()
            },
            rule.listen_port
        );
        let value = format!("{}/{}", rule.connect_address, rule.connect_port);
        unsafe {
            let mut raw = HKEY::default();
            check(
                RegCreateKeyExW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(wide(KEY).as_ptr()),
                    0,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    None,
                    &mut raw,
                    None,
                ),
                "RegCreateKeyExW(PortProxy)",
            )?;
            let key = Key(raw);
            let name = wide(&name);
            let status = RegQueryValueExW(key.0, PCWSTR(name.as_ptr()), None, None, None, None);
            if status == ERROR_SUCCESS {
                return Err("A portproxy rule for this listener already exists".into());
            }
            if status != ERROR_FILE_NOT_FOUND {
                check(status, "RegQueryValueExW(PortProxy)")?;
            }
            let bytes: Vec<u8> = wide(&value).iter().flat_map(|x| x.to_le_bytes()).collect();
            check(
                RegSetValueExW(key.0, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(&bytes)),
                "RegSetValueExW(PortProxy)",
            )?;
            if let Err(e) = notify() {
                let _ = RegDeleteValueW(key.0, PCWSTR(name.as_ptr()));
                return Err(e);
            }
        }
        Ok(())
    }
    fn delete_portproxy(&mut self) -> Result<()> {
        let key = open_key(KEY_SET_VALUE)
            .map_err(|e| format!("RegOpenKeyExW(PortProxy) failed (Win32 code {})", e.0))?;
        unsafe {
            let mut status = RegDeleteValueW(key.0, PCWSTR(wide("*/8180").as_ptr()));
            if status == ERROR_FILE_NOT_FOUND {
                status = RegDeleteValueW(key.0, PCWSTR(wide("0.0.0.0/8180").as_ptr()));
            }
            check(status, "RegDeleteValueW(PortProxy)")?;
        }
        notify()
    }
    fn add_firewall(&mut self) -> Result<()> {
        let _com = Apartment::new()?;
        unsafe {
            let rules = rules()?;
            let name = BSTR::from("proxy forward");
            match rules.Item(&name) {
                Ok(_) => return Err("A firewall rule with this name already exists".into()),
                Err(e) if e.code().0 as u32 == 0x80070002 => {}
                Err(e) => return Err(format!("INetFwRules::Item failed: {e}")),
            }
            let rule: INetFwRule = api(
                CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER),
                "CoCreateInstance(NetFwRule)",
            )?;
            api(rule.SetName(&name), "SetName")?;
            api(rule.SetDirection(NET_FW_RULE_DIR_IN), "SetDirection")?;
            api(rule.SetProtocol(6), "SetProtocol")?;
            api(rule.SetLocalPorts(&BSTR::from("8180")), "SetLocalPorts")?;
            api(rule.SetAction(NET_FW_ACTION_ALLOW), "SetAction")?;
            api(rule.SetProfiles(NET_FW_PROFILE2_ALL.0), "SetProfiles")?;
            api(rule.SetEnabled(VARIANT_TRUE), "SetEnabled")?;
            api(rules.Add(&rule), "INetFwRules::Add")
        }
    }
    fn delete_firewall(&mut self) -> Result<()> {
        let _com = Apartment::new()?;
        unsafe {
            api(
                rules()?.Remove(&BSTR::from("proxy forward")),
                "INetFwRules::Remove",
            )
        }
    }
}
