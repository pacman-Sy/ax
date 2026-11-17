//! Working out how the far side should reach a listener that is already bound.

use std::net::IpAddr;

use crate::netinfo;
use crate::upnp;

pub struct Endpoint {
    pub ip: IpAddr,
    /// The host's own LAN address for the same listener, when it has one.
    pub alt: Option<IpAddr>,
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

/// Public address if one answers quickly, otherwise the LAN address so the
/// command still produces a usable code instead of failing outright.
fn discover_or_lan(local: Option<IpAddr>) -> Result<IpAddr, String> {
    match netinfo::public_ip() {
        Ok(ip) => Ok(ip),
        Err(e) => match local {
            Some(ip) if !ip.is_unspecified() => {
                eprintln!("ax: public address lookup failed ({e}), using the LAN address");
                Ok(ip)
            }
            _ => Err(e),
        },
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

    let local = netinfo::local_ip().ok();

    let ip = match pinned_host {
        Some(ip) => ip,
        None => match &mapper {
            Some(m) => match m.external_ip() {
                Ok(ip) if !netinfo::is_private(ip) => ip,
                _ => discover_or_lan(local)?,
            },
            None => discover_or_lan(local)?,
        },
    };

    if !mapped && pinned_host.is_none() && netinfo::is_private(ip) {
        // Advertising a LAN address is honest but only useful on that network;
        // say so loudly instead of letting the far side time out silently.
        eprintln!(
            "ax: no port mapping and no public address — this code only works on the local \
             network ({ip}); forward tcp/{port} on the router and rerun with -host <public-ip> \
             for internet use"
        );
    } else if !mapped && pinned_host.is_none() {
        // A public address was discovered, but nothing opened the port. That
        // address is a guess about the router, not a promise, and the far side
        // pays for the guess with a full timeout.
        eprintln!(
            "ax: warning: no port mapping — tcp/{port} is not open from outside.\n\
             \x20 this code only works if you already forward tcp/{port} to this machine.\n\
             \x20 enable UPnP/IGD on the router and rerun, or forward the port yourself and\n\
             \x20 rerun with -no-map -host <public-ip> -pub-port <forwarded-port>.\n\
             \x20 a container, VM or CGNAT host cannot accept inbound at all."
        );
    }

    // Same-network callers cannot always reach the public address (many
    // routers will not hairpin), so carry the LAN address as well and let the
    // far side try it first.
    let alt = local.filter(|lan| netinfo::is_private(*lan) && *lan != ip && !lan.is_unspecified());

    Ok(Endpoint {
        ip,
        alt,
        port,
        mapper,
        mapped,
    })
}
