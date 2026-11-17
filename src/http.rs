//! Just enough HTTP to talk to a gateway's description endpoint and to a plain
//! text address echo. No TLS: every URL used here is http on the LAN or a
//! provider that still answers plain http.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse(url: &str) -> Result<Url, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only plain http is supported: {url}"))?;

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?,
        ),
        None => (authority.to_string(), 80u16),
    };

    if host.is_empty() {
        return Err(format!("no host in {url}"));
    }

    Ok(Url {
        host,
        port,
        path: path.to_string(),
    })
}

pub fn get(url: &str) -> Result<String, String> {
    request(url, "GET", &[], "")
}

pub fn post(url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, String> {
    request(url, "POST", headers, body)
}

fn request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<String, String> {
    let u = parse(url)?;

    let mut stream = TcpStream::connect((u.host.as_str(), u.port))
        .map_err(|e| format!("connect {}:{}: {e}", u.host, u.port))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));

    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ax\r\nAccept: */*\r\nConnection: close\r\n",
        u.path, u.host
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("send to {}: {e}", u.host))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read from {}: {e}", u.host))?;

    let (head, body) = split_response(&raw)?;
    let status = status_code(head)?;
    if status != 200 {
        return Err(format!("{method} {url}: http {status}"));
    }

    if header(head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        decode_chunked(body)
    } else {
        Ok(String::from_utf8_lossy(body).into_owned())
    }
}

fn split_response(raw: &[u8]) -> Result<(&str, &[u8]), String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed http response".to_string())?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|_| "non-utf8 headers".to_string())?;
    Ok((head, &raw[sep + 4..]))
}

fn status_code(head: &str) -> Result<u16, String> {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "malformed http status line".to_string())
}

pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn decode_chunked(mut body: &[u8]) -> Result<String, String> {
    let mut out = Vec::with_capacity(body.len());

    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunk header".to_string())?;
        let line = std::str::from_utf8(&body[..line_end])
            .map_err(|_| "malformed chunk header".to_string())?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("bad chunk size {size_text:?}"))?;

        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        if body.len() < size {
            return Err("truncated chunk".into());
        }
        out.extend_from_slice(&body[..size]);
        body = body.get(size + 2..).unwrap_or(&[]);
    }

    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let u = parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(u.host, "192.168.1.1");
        assert_eq!(u.port, 5000);
        assert_eq!(u.path, "/rootDesc.xml");

        let u = parse("http://icanhazip.com").unwrap();
        assert_eq!(u.host, "icanhazip.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn decodes_chunked_body() {
        let body = b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), "wikipedia");
    }
}
