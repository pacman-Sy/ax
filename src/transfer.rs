//! File transfer over the same tunnel. Sender streams, receiver verifies a
//! SHA-256 of the whole file before the temporary name is renamed into place.

use std::io::{Read, Write};

use std::fs::File;
use std::net::{IpAddr, TcpListener};
use std::path::Path;
use std::time::Duration;

use crate::cli::Args;
use crate::code::{Code, KIND_UPLOAD, SECRET_LEN};
use crate::crypto::Sha256;
use crate::expose;
use crate::netinfo;
use crate::rand;
use crate::tunnel::{self, Tunnel};

const MAX_NAME_LEN: usize = 1024;
const MAX_SIZE: u64 = 1 << 40;
const TAG_LEN: usize = 32;

struct Header {
    name: String,
    size: u64,
    sum: [u8; 32],
}

pub fn upload(raw: &[String]) -> Result<(), String> {
    let args = Args::parse(raw);
    let bind = args.string("bind", "0.0.0.0");
    let port = args.int("port", 0)?;
    let no_map = args.flag("no-map");

    let pinned_host = match args.get("host") {
        Some(text) => Some(
            text.parse::<IpAddr>()
                .map_err(|_| format!("-host {text}: not an address"))?,
        ),
        None => None,
    };
    let pinned_port = match args.get("pub-port") {
        Some(_) => {
            let value = args.int("pub-port", 0)?;
            if !(1..=65535).contains(&value) {
                return Err(format!("-pub-port {value} is out of range"));
            }
            Some(value as u16)
        }
        None => None,
    };

    if args.positional.is_empty() {
        return Err("usage: ax upload <file>".into());
    }
    let path = args.positional[0].clone();

    let (sum, size) = hash_file(&path)?;

    let listener = TcpListener::bind((bind.as_str(), port as u16))
        .map_err(|e| format!("listen on {bind}:{port}: {e}"))?;
    let internal = listener
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?
        .port();

    let endpoint = expose::expose_tcp(internal, pinned_host, pinned_port, no_map, "ax transfer")?;

    let secret: [u8; SECRET_LEN] = rand::bytes()?;
    let code = Code::new(KIND_UPLOAD, endpoint.ip, endpoint.port, secret)?;

    eprintln!("ax: sharing {} ({})", base_name(&path), human(size));
    println!("{}", code.encode());
    eprintln!(
        "\nthe other machine runs:\n  ax download {}\n\nwaiting for the receiver",
        code.encode()
    );

    loop {
        let (sock, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;

        let tunnel = match tunnel::server(sock, &secret) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ax: rejected a caller: {e}");
                continue;
            }
        };

        if let Err(e) = send_file(tunnel, &path, sum, size) {
            eprintln!("ax: {e}");
            continue;
        }
        return Ok(());
    }
}

fn send_file(mut tunnel: Tunnel, path: &str, sum: [u8; 32], size: u64) -> Result<(), String> {
    let header = Header {
        name: base_name(path),
        size,
        sum,
    };
    write_header(&mut tunnel, &header)?;

    let mut file = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let sent = copy_with_progress(&mut file, &mut tunnel, size)?;

    if sent != size {
        return Err(format!(
            "sent {sent} of {size} bytes, receiver will reject it"
        ));
    }

    tunnel.tx.flush().map_err(|e| format!("flush: {e}"))?;
    eprintln!("ax: sent {}", human(sent));
    Ok(())
}

pub fn download(raw: &[String]) -> Result<(), String> {
    let args = Args::parse(raw);
    let out_dir = args.string("out", ".");
    let timeout = args.int("timeout", 15)?;

    if args.positional.is_empty() {
        return Err("usage: ax download <code>".into());
    }

    let code = Code::parse(KIND_UPLOAD, &args.positional[0])?;

    let sock = netinfo::dial(code.addr(), Duration::from_secs(timeout as u64))?;
    let tunnel = tunnel::client(sock, &code.secret)?;

    receive_file(tunnel, &out_dir)
}

fn receive_file(mut tunnel: Tunnel, out_dir: &str) -> Result<(), String> {
    let header = read_header(&mut tunnel)?;

    std::fs::create_dir_all(out_dir).map_err(|e| format!("create {out_dir}: {e}"))?;

    let dest = Path::new(out_dir).join(&header.name);
    let part = Path::new(out_dir).join(format!("{}.part", header.name));

    let mut file = File::create(&part).map_err(|e| format!("create {}: {e}", part.display()))?;
    let got = copy_with_progress(&mut tunnel, &mut file, header.size)?;

    if let Err(e) = file.flush() {
        let _ = std::fs::remove_file(&part);
        return Err(format!("flush: {e}"));
    }
    drop(file);

    if got != header.size {
        let _ = std::fs::remove_file(&part);
        return Err(format!(
            "short transfer: got {got} of {} bytes",
            header.size
        ));
    }

    let (sum, _) = hash_file(part.to_str().unwrap_or(""))?;
    if sum != header.sum {
        let _ = std::fs::remove_file(&part);
        return Err("checksum mismatch, partial file discarded".into());
    }

    std::fs::rename(&part, &dest).map_err(|e| format!("rename to {}: {e}", dest.display()))?;

    eprintln!("ax: wrote {} ({})", dest.display(), human(header.size));
    Ok(())
}

fn write_header<W: Write>(w: &mut W, header: &Header) -> Result<(), String> {
    let name = header.name.as_bytes();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err("file name cannot be sent".into());
    }
    if header.size > MAX_SIZE {
        return Err("file is larger than this format allows".into());
    }

    w.write_all(&(name.len() as u16).to_be_bytes())
        .map_err(|e| e.to_string())?;
    w.write_all(name).map_err(|e| e.to_string())?;
    w.write_all(&header.size.to_be_bytes())
        .map_err(|e| e.to_string())?;
    w.write_all(&header.sum).map_err(|e| e.to_string())?;
    Ok(())
}

fn read_header<R: Read>(r: &mut R) -> Result<Header, String> {
    let mut len_bytes = [0u8; 2];
    r.read_exact(&mut len_bytes)
        .map_err(|e| format!("read name length: {e}"))?;
    let name_len = u16::from_be_bytes(len_bytes) as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return Err(format!("sender offered a bad name length {name_len}"));
    }

    let mut name = vec![0u8; name_len];
    r.read_exact(&mut name).map_err(|e| e.to_string())?;
    let name = String::from_utf8(name).map_err(|_| "sender offered a non-utf8 name".to_string())?;
    let name = base_name(&name);

    let mut size_bytes = [0u8; 8];
    r.read_exact(&mut size_bytes).map_err(|e| e.to_string())?;
    let size = u64::from_be_bytes(size_bytes);
    if size > MAX_SIZE {
        return Err(format!("sender offered an oversized file ({size} bytes)"));
    }

    let mut sum = [0u8; TAG_LEN];
    r.read_exact(&mut sum).map_err(|e| e.to_string())?;

    Ok(Header { name, size, sum })
}

fn base_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .unwrap_or_else(|| "download.bin".into())
}

fn hash_file(path: &str) -> Result<([u8; 32], u64), String> {
    let mut file = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }

    Ok((hasher.finalize(), total))
}

fn copy_with_progress<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    total: u64,
) -> Result<u64, String> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    let mut last = 101u64;

    loop {
        let n = from.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n]).map_err(|e| format!("write: {e}"))?;
        done += n as u64;

        let pct = if total > 0 { done * 100 / total } else { 0 };
        if pct != last {
            last = pct;
            eprint!("\r  {pct:3}%  {} / {}", human(done), human(total));
        }
    }
    eprintln!();

    Ok(done)
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;
    use std::io;

    #[test]
    fn header_round_trip() {
        let header = Header {
            name: "notes.txt".into(),
            size: 4096,
            sum: sha256(b"x"),
        };

        let mut wire = Vec::new();
        write_header(&mut wire, &header).unwrap();

        let mut cursor = io::Cursor::new(wire);
        let back = read_header(&mut cursor).unwrap();

        assert_eq!(back.name, "notes.txt");
        assert_eq!(back.size, 4096);
        assert_eq!(back.sum, header.sum);
    }

    #[test]
    fn strips_paths_from_names() {
        assert_eq!(base_name("../../etc/passwd"), "passwd");
        assert_eq!(base_name("/tmp/thing.tar.gz"), "thing.tar.gz");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2.0 KB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MB");
    }
}
