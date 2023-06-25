use std::env;
use std::io::Result;
use std::net::{IpAddr, UdpSocket, SocketAddr, Ipv4Addr};
use aes_gcm::aead::heapless;

use udp_obfs::aes::{AES, NONCELEN, BUFSIZE};

fn main() -> Result<()> {
    if let Some(arg) = env::args().nth(1) {
        if arg == "s" {
            println!("starting as server");
            return server();
        }
        else if arg == "c" {
            println!("starting as client");
            return client();
        }
    }
    
    panic!("need a valid argument: s(erver) or c(lient)")
}

fn client() -> Result<()> {
    // TODO: read port from addr
    let src = "0.0.0.0:51821";
    let socket = UdpSocket::bind(&src).expect("could not bind to address");
    println!("listening on {}", &src);

    // TODO: read addr from config
    let localwg_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820);
    let remote_proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(185, 240, 247, 233)), 51821);

    println!("local wg addr: {:?}", localwg_addr);
    println!("remote proxy addr: {:?}", remote_proxy_addr);

    let secret = base64::encode("i am your client: secret123");
    println!("secret: \"{}\"", &secret);

    socket.send_to(secret.as_bytes(), remote_proxy_addr).expect("could not send init proxy handshake to server");

    // TODO: read key from config
    let aes = AES::new(b"this is my key..");

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
    let mut counter = 0u64;
    loop {
        // println!();

        buf.resize(BUFSIZE, 0).unwrap();
        let (n, src_addr) = socket.recv_from(&mut buf[..]).expect("could not read from address");
        buf.truncate(n);
        // println!("recieved {} bytes from {}", n, &src_addr);

        let dst_addr: SocketAddr;
        if src_addr == localwg_addr {
            // println!("forwarding to remote proxy");
            let msg = aes.encrypt(counter, &mut buf);
            dst_addr = remote_proxy_addr;
            socket.send_to(msg, dst_addr).expect("could not write to client");
            counter = if counter == u64::MAX { 0 } else { counter + 1 };
        } 
        else if src_addr == remote_proxy_addr {
            // println!("forwarding to local proxy");
            let msg = match aes.decrypt(&mut buf) {
                Ok(x) => x,
                Err(_) => continue
            };
            dst_addr = localwg_addr;
            socket.send_to(&msg, dst_addr).expect("could not write to client");
        }
        else {
            continue;
        }

        buf.clear();

        // socket.send_to(&msg, dst_addr).expect("could not write to client");
    }
}


fn server() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:51821").expect("could not bind to address");
    println!("listening on :51821");

    let wgsrv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 55, 33, 1)), 51820); 

    let secret = base64::encode("i am your client: secret123");
    println!("secret: \"{}\"", &secret);

    let mut client_addr: Option<SocketAddr> = None;

    let aes = AES::new(b"this is my key..");

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
    let mut counter = 0u64;

    loop {
        // println!();

        buf.resize(BUFSIZE, 0).unwrap();
        let (n, src_addr) = socket.recv_from(&mut buf[..]).expect("could not read from address");
        buf.truncate(n);
        // println!("recieved {} bytes from {}", n, &src_addr);

        if src_addr == wgsrv_addr {
            // println!("wg server sent this! forwarded to remote client");
            if let Some(dst) = client_addr {
                //encrypt
                let msg = aes.encrypt(counter, &mut buf);
                socket.send_to(msg, dst).expect("could not write to client");
                counter = if counter == u64::MAX { 0 } else { counter + 1 };
            }
            continue;
        }

        if n == secret.len() {
            if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                if s == secret {
                    println!("new client set to {}", src_addr);
                    client_addr = Some(src_addr);
                    continue;
                }
            }
        }

        if let Some(_) = client_addr {
            if n < NONCELEN {
                continue;
            }
            let msg = match aes.decrypt(&mut buf) {
                Ok(x) => x,
                Err(_) => continue
            };
            socket.send_to(&msg[..], wgsrv_addr).expect("could not write to wg server");
            // println!("forwarded to wg server")
        }
    }
}
