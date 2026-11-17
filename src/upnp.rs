//! UPnP IGD: find the gateway over SSDP, read its description, and ask it to
//! forward a port. Everything here is string and byte work — no XML crate.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::http;

const SSDP_ADDR: &str = "239.255.255.250:1900";
const LEASE_SECS: u32 = 7200;

pub struct Mapper {
    control_url: String,
    service_type: String,
    base_host: String,
    base_port: u16,
}

impl Mapper {
    pub fn describe(&self) -> String {
        format!("upnp {}", self.service_type)
    }

    pub fn external_ip(&self) -> Result<IpAddr, String> {
        let body = self.soap("GetExternalIPAddress", "")?;
        let text = tag_text(&body, "NewExternalIPAddress")
            .ok_or_else(|| "gateway did not report an external address".to_string())?;
        text.trim()
            .parse::<IpAddr>()
            .map_err(|_| format!("gateway reported {text:?}, not an address"))
    }

    pub fn map_tcp(
        &self,
        internal_port: u16,
        external_port: u16,
        desc: &str,
    ) -> Result<u16, String> {
        let host = crate::netinfo::local_ip()?;

        let inner = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>\
             <NewInternalPort>{internal_port}</NewInternalPort>\
             <NewInternalClient>{host}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{desc}</NewPortMappingDescription>\
             <NewLeaseDuration>{LEASE_SECS}</NewLeaseDuration>"
        );

        self.soap("AddPortMapping", &inner)?;
        Ok(external_port)
    }

    pub fn unmap_tcp(&self, external_port: u16) -> Result<(), String> {
        let inner = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>"
        );
        self.soap("DeletePortMapping", &inner).map(|_| ())
    }

    fn soap(&self, action: &str, inner: &str) -> Result<String, String> {
        let envelope = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:{action} xmlns:u=\"{}\">{inner}</u:{action}></s:Body></s:Envelope>",
            self.service_type
        );

        let soap_action = format!("\"{}#{action}\"", self.service_type);
        let headers: [(&str, &str); 2] = [
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPAction", soap_action.as_str()),
        ];

        // The description told us which host answered; reuse it so a gateway
        // that advertises a hostname we cannot resolve still works.
        let url = if self.control_url.starts_with("http://") {
            self.control_url.clone()
        } else {
            format!(
                "http://{}:{}{}",
                self.base_host, self.base_port, self.control_url
            )
        };

        let body = http::post(&url, &headers, &envelope)?;

        if let Some(err) = tag_text(&body, "errorDescription") {
            return Err(format!("{action}: {}", err.trim()));
        }
        Ok(body)
    }
}

pub fn discover() -> Result<Mapper, String> {
    let locations = ssdp_locations(Duration::from_secs(3));
    if locations.is_empty() {
        return Err("no IGD answered SSDP".into());
    }

    let mut first_err: Option<String> = None;
    for loc in &locations {
        match from_location(loc) {
            Ok(mapper) => return Ok(mapper),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    Err(first_err.unwrap_or_else(|| "no usable gateway description".into()))
}

fn ssdp_locations(timeout: Duration) -> Vec<String> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let target = match SSDP_ADDR.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };

    let searches = [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];

    for st in searches {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
        );
        let _ = sock.send_to(msg.as_bytes(), target);
    }

    let _ = sock.set_read_timeout(Some(timeout));

    let mut found = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                if let Some(loc) = http::header(&text, "location") {
                    if !found.iter().any(|f: &String| f == loc) {
                        found.push(loc.to_string());
                    }
                }
                if found.len() >= 4 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    found
}

fn from_location(loc: &str) -> Result<Mapper, String> {
    let parsed = http::parse(loc)?;
    let desc = http::get(loc)?;

    for block in blocks(&desc, "service") {
        let service_type = tag_text(block, "serviceType").unwrap_or_default();
        if !(service_type.contains("WANIPConnection") || service_type.contains("WANPPPConnection"))
        {
            continue;
        }
        let control = tag_text(block, "controlURL").unwrap_or_default();
        if control.is_empty() {
            continue;
        }

        let control = if control.starts_with("http://") {
            control
        } else if control.starts_with('/') {
            format!("http://{}:{}{}", parsed.host, parsed.port, control)
        } else {
            format!("http://{}:{}/{}", parsed.host, parsed.port, control)
        };

        return Ok(Mapper {
            control_url: control,
            service_type,
            base_host: parsed.host,
            base_port: parsed.port,
        });
    }

    Err("gateway description had no WAN connection service".into())
}

/// Returns the inner text of every `<tag>...</tag>` in the document.
fn blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut pos = 0;

    while let Some(i) = xml[pos..].find(&open) {
        let start = pos + i;
        let after = match xml[start..].find('>') {
            Some(j) => start + j + 1,
            None => break,
        };
        let end = match xml[after..].find(&close) {
            Some(j) => after + j,
            None => break,
        };
        out.push(&xml[after..end]);
        pos = end + close.len();
    }

    out
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");

    let start = xml.find(&open)?;
    let after = start + xml[start..].find('>')? + 1;
    let end = after + xml[after..].find(&close)?;

    Some(xml[after..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_tag_text() {
        let xml = "<r><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></r>";
        assert_eq!(
            tag_text(xml, "NewExternalIPAddress").unwrap(),
            "203.0.113.9"
        );
    }

    #[test]
    fn finds_service_blocks() {
        let xml = "<root><service><serviceType>urn:WANIPConnection:1</serviceType>\
                   <controlURL>/ctl/IPConn</controlURL></service></root>";
        let found = blocks(xml, "service");
        assert_eq!(found.len(), 1);
        assert!(tag_text(found[0], "serviceType")
            .unwrap()
            .contains("WANIPConnection"));
    }
}
