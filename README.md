# ax

Peer-to-peer ssh relay and file transfer where the connection details live inside the code you send. No account, no rendezvous server, no relay: the far side dials your machine directly, over the internet, and everything on the wire is encrypted and authenticated end to end.

```
ax startssh                     # prints a code, waits
ax connectssh <code>            # on the other machine: dials, tunnels, runs ssh
ax upload build.tar.gz          # prints a code for the file
ax download <code>              # fetches it, verifies the checksum
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/pacman-Sy/ax/main/install.sh | bash
```

Builds from source with cargo and drops the binary in `~/.local/bin` (`AX_PREFIX` to change it).

Or build it yourself:

```sh
git clone https://github.com/pacman-Sy/ax && cd ax
cargo build --release      # target/release/ax, no dependencies to download
```

Rust 1.70+, Linux / macOS / Windows, zero crates.

## Why there is no middle server

A code carries everything the other side needs:

```
AR2X-6AAA-AGD5-TAD4-JES5-ZIRP-XGXU-GNQG-UQ7L-3BA
```

That is base32 of a fixed binary record: version, purpose (`ssh` or `upload`), the host address (4 bytes IPv4 or 16 bytes IPv6), the port, and a 128-bit secret. The code is a signed-in-spirit description of *where* to connect and *what* to say when it gets there — the client dials the address directly. Nothing is looked up, nothing is brokered, nothing is stored.

## Getting through the internet, not just the LAN

`startssh` and `upload` work out how a remote peer should reach an already-bound listener:

1. Pinned values win: `-host` (address to advertise) and `-pub-port` (public port, when you already forward one).
2. Otherwise it asks the gateway for a forwarding rule over UPnP IGD (SSDP discovery, `AddPortMapping` with a 2 hour lease, removed on exit).
3. It then learns the public address: the gateway's `ExternalIPAddress`, or STUN, or a plain HTTP echo as a last resort.

If no mapping could be arranged it says so and leaves the port alone, so a manual forward still works.

Flags that override all of that:

```
startssh  -bind 0.0.0.0  -port 0  -ssh-port 22  -target 127.0.0.1
          -host <ip-or-name>  -pub-port <n>  -no-map
upload    -bind 0.0.0.0  -port 0  -host <ip-or-name>  -pub-port <n>  -no-map
connectssh -ssh ssh  -timeout 15
download   -out .  -timeout 15
```

## Encryption

Every connection runs a handshake before a single byte of user data moves:

- **X25519** ephemeral key agreement (RFC 7748), fresh per session, so a leaked code does not unlock traffic recorded earlier.
- **HKDF-SHA256** key schedule (RFC 5869) salted with the 128-bit code secret — knowing the code is what makes the derived keys the right ones.
- **ChaCha20** for confidentiality, one key per direction, with a per-frame counter nonce.
- **HMAC-SHA256** per frame, encrypt-then-MAC, covering the length and ciphertext.
- **Mutual authentication**: each side proves it holds the code by sending an HMAC over the handshake transcript. A relay, a port-forward, or anyone who guessed the address is rejected before any data flows, and cannot read, alter, or inject anything.

All primitives are implemented in-tree against their published test vectors (SHA-256, HMAC, HKDF, X25519 RFC 7748 §5.2, ChaCha20 cross-checked with OpenSSL), so the binary has no third-party code to trust.

## ssh relay

```
# on the machine you want to reach
$ ax startssh
ax: forwarding 203.0.113.7:41633 -> 127.0.0.1:22
AR2X-6AAA-AGD5-TAD4-JES5-ZIRP-XGXU-GNQG-UQ7L-3BA

on the other machine:
  ax connectssh AR2X-6AAA-AGD5-TAD4-JES5-ZIRP-XGXU-GNQG-UQ7L-3BA

# on your laptop
$ ax connectssh AR2X-6AAA-AGD5-TAD4-JES5-ZIRP-XGXU-GNQG-UQ7L-3BA alice
ax: tunnel on 127.0.0.1:45487, launching ssh
```

`connectssh` opens an encrypted tunnel, then runs your system `ssh` against `127.0.0.1:<local port>` with `StrictHostKeyChecking=accept-new`. sshd does its own multiplexing inside that single stream, so a tunnel is all that is needed. `-ssh <path>` picks a different ssh binary, `-ssh-port` points the relay at a non-standard sshd, `-target` relays to another host on the listener's network.

## File transfer

```
# sender
$ ax upload backup.tar.gz
ax: sharing backup.tar.gz (1.4 GB)
<code>

# receiver
$ ax download <code> -out ./incoming
 100%  1.4 GB / 1.4 GB
ax: wrote incoming/backup.tar.gz (1.4 GB)
```

The sender streams into the tunnel; the receiver writes `name.part`, checks the byte count, recomputes SHA-256 over what actually landed, and only then renames into place. A truncated or corrupted transfer leaves nothing behind. Paths are stripped from the offered name, so a file always lands inside `-out`.

## Tests

```sh
cargo test
```

Covers SHA-256 and HMAC vectors, HKDF, X25519 RFC 7748 §5.2, ChaCha20 against an OpenSSL vector, code round-trips for IPv4 and IPv6, the transfer header, the UPnP response parser, and a full two-sided encrypted tunnel including rejection of a peer without the code.

## License

MIT. See [LICENSE](LICENSE).
