//! Copying between two connections where either side may be encrypted.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

use crate::tunnel::Tunnel;

pub trait Splittable {
    fn split_io(self) -> (Box<dyn Read + Send>, Box<dyn Write + Send>);
    fn halt_handle(&self) -> Option<TcpStream>;
}

impl Splittable for TcpStream {
    fn split_io(self) -> (Box<dyn Read + Send>, Box<dyn Write + Send>) {
        match self.try_clone() {
            Ok(other) => (Box::new(self), Box::new(other)),
            Err(_) => (Box::new(self), Box::new(io::sink())),
        }
    }

    fn halt_handle(&self) -> Option<TcpStream> {
        self.try_clone().ok()
    }
}

impl Splittable for Tunnel {
    fn split_io(self) -> (Box<dyn Read + Send>, Box<dyn Write + Send>) {
        (Box::new(self.rx), Box::new(self.tx))
    }

    fn halt_handle(&self) -> Option<TcpStream> {
        self.rx.sock.try_clone().ok()
    }
}

/// Pumps both directions until one closes, then shuts both sockets so the other
/// copy unblocks instead of hanging forever.
pub fn splice<A: Splittable, B: Splittable>(a: A, b: B) {
    let halt_a = a.halt_handle();
    let halt_b = b.halt_handle();

    let (a_read, a_write) = a.split_io();
    let (b_read, b_write) = b.split_io();

    let pump = std::thread::spawn(move || {
        let mut from = b_read;
        let mut to = a_write;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.flush();
    });

    {
        let mut from = a_read;
        let mut to = b_write;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.flush();
    }

    if let Some(sock) = halt_b {
        let _ = sock.shutdown(Shutdown::Both);
    }
    if let Some(sock) = halt_a {
        let _ = sock.shutdown(Shutdown::Both);
    }

    let _ = pump.join();
}
