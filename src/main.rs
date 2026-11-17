mod chacha;
mod cli;
mod code;
mod crypto;
mod expose;
mod http;
mod netinfo;
mod rand;
mod splice;
mod ssh;
mod stun;
mod transfer;
mod tunnel;
mod upnp;
mod x25519;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        usage();
        std::process::exit(2);
    }

    let rest = &args[1..];
    let result = match args[0].as_str() {
        "startssh" => ssh::start(rest),
        "connectssh" => ssh::connect(rest),
        "upload" => transfer::upload(rest),
        "download" => transfer::download(rest),
        "version" | "-v" | "--version" => {
            println!("ax {VERSION}");
            Ok(())
        }
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        unknown => {
            eprintln!("ax: unknown command {unknown:?}\n");
            usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("ax: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "ax — peer-to-peer ssh relay and file transfer, no middle server

  ax startssh [flags]              listen, print a code for the other side
  ax connectssh <code> [user]      dial that code and open ssh through it
  ax upload <file> [flags]         serve a file, print a code to share
  ax download <code> [flags]       pull the file the code points at

flags:
  startssh   -bind 0.0.0.0  -port 0  -ssh-port 22  -target 127.0.0.1
             -host <ip-or-name>  -pub-port <n>  -no-map
  upload     -bind 0.0.0.0  -port 0  -host <ip-or-name>  -pub-port <n>  -no-map
  connectssh -ssh ssh  -timeout 15  -v
  download   -out .  -timeout 15  -v

The code carries the public address, the host's LAN address (when it has one),
the port, the purpose and a 128-bit secret; the far side needs nothing else.
Dialling tries the LAN address first, so two machines on one network work even
when the router will not hairpin the public address. -v shows each attempt. -no-map skips the gateway port mapping when the port is
already forwarded.

Every session is X25519 key agreement, HKDF-SHA256 key schedule, ChaCha20 for
confidentiality and HMAC-SHA256 per frame. The code secret authenticates both
ends, so a relay in the path cannot read, alter, or impersonate the stream."
    );
}
