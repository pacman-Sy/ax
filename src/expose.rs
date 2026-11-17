//! Working out how the far side should reach a listener that is already bound.

use std::net::IpAddr;

use crate::netinfo;
use crate::upnp;

pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
    mapper: Option<upnp::Mapper>,
    mapped: bool,
}

impl Drop for Endpoint {
    /// Best effort: remove the forwarding rule on the way out. The lease also
    /// expires on its own if this process is killed outright.
    fn drop(&mut self) {
        if self.mapped {
            if let Some(mapper) = &self.mapper {
                let _ = mapper.unmap_tcp(self.port);
            }
        }
    }
}

/// Order of preference: a port the caller pinned, a gateway mapping, then a
/// plain public-address lookup with the port left as-is.
pub fn expose_tcp(
    internal_port: u16,
    pinned_host: Option<IpAddr>,
    pinned_port: Option<u16>,
    no_map: bool,
    desc: &str,
) -> Result<Endpoint, String> {
    let mut port = pinned_port.unwrap_or(internal_port);
    let mut mapper: Option<upnp::Mapper> = None;

    if !no_map && pinned_port.is_none() {
        match upnp::discover() {
            Ok(found) => match found.map_tcp(internal_port, port, desc) {
                Ok(external) => {
                    port = external;
                    eprintln!("ax: mapped tcp/{port} via {}", found.describe());
                    mapper = Some(found);
                }
                Err(e) => {
                    eprintln!("ax: port mapping refused ({e}), falling back to address discovery")
                }
            },
            Err(e) => eprintln!("ax: no gateway mapping ({e}), falling back to address discovery"),
        }
    }

    let mapped = mapper.is_some();

    let ip = match pinned_host {
        Some(ip) => ip,
        None => match &mapper {
            Some(m) => match m.external_ip() {
                Ok(ip) if !netinfo::is_private(ip) => ip,
                _ => netinfo::public_ip()?,
            },
            None => netinfo::public_ip()?,
        },
    };

    if !mapped && pinned_host.is_none() {
        eprintln!(
            "ax: note: no automatic port forward — the router must already forward tcp/{port}"
        );
    }

    Ok(Endpoint {
        ip,
        port,
        mapper,
        mapped,
    })
}
