use aes_gcm::aead::heapless;
use clap::{Parser, Subcommand};
use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

use udp_obfs::aes::{AES, BUFSIZE, NONCELEN};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
struct Cli {
    #[command(subcommand)]
    mode: Modes,
}

#[derive(Subcommand, Debug)]
enum Modes {
    // #[command(arg_required_else_help = true)]
    Client,
    // #[command(arg_required_else_help = true)]
    Server,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.mode {
        Modes::Client => client().await,
        Modes::Server => server().await,
    }
}

async fn client() -> Result<()> {
    // TODO: read port from addr
    let src = "127.0.0.1:51821";
    // let src = "0.0.0.0:51821";
    let socket = UdpSocket::bind(&src)
        .await
        .expect("could not bind to address");
    println!("listening on {}", &src);

    // TODO: read addr from config
    let localwg_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820);
    let remote_proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51822);

    println!("local wg addr: {:?}", localwg_addr);
    println!("remote proxy addr: {:?}", remote_proxy_addr);

    let secret = "i am your client: secret123";
    println!("secret: \"{}\"", &secret);

    socket
        .send_to(secret.as_bytes(), remote_proxy_addr)
        .await
        .expect("could not send init proxy handshake to server");

    // TODO: read key from config
    let aes = AES::new(b"this is my key..");

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
    let mut counter = 0u64;
    loop {
        // println!();
        buf.resize(BUFSIZE, 0).unwrap();
        let (n, src_addr) = socket
            .recv_from(&mut buf[..])
            .await
            .expect("could not read from address");
        buf.truncate(n);
        // println!("recieved {} bytes from {}", n, &src_addr);

        let dst_addr: SocketAddr;
        if src_addr == localwg_addr {
            // println!("forwarding to remote proxy");
            let msg = aes.encrypt(counter, &mut buf);
            dst_addr = remote_proxy_addr;
            socket
                .send_to(msg, dst_addr)
                .await
                .expect("could not write to client");
            counter = if counter == u64::MAX { 0 } else { counter + 1 };
        } else if src_addr == remote_proxy_addr {
            // println!("forwarding to local proxy");
            let msg = match aes.decrypt(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            dst_addr = localwg_addr;
            socket
                .send_to(&msg, dst_addr)
                .await
                .expect("could not write to client");
        } else {
            print!("{:?}", src_addr);
            continue;
        }

        buf.clear();

        // socket.send_to(&msg, dst_addr).expect("could not write to client");
    }
}

async fn server() -> Result<()> {
    // let socket = UdpSocket::bind("0.0.0.0:51821")
    let socket = UdpSocket::bind("127.0.0.1:51822")
        .await
        .expect("could not bind to address");
    println!("listening on :51822");

    let wgsrv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51823);

    let secret = "i am your client: secret123";
    println!("secret: \"{}\"", &secret);

    let mut client_addr: Option<SocketAddr> = None;

    let aes = AES::new(b"this is my key..");

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
    let mut counter = 0u64;

    loop {
        // println!();

        buf.resize(BUFSIZE, 0).unwrap();
        let (n, src_addr) = socket
            .recv_from(&mut buf[..])
            .await
            .expect("could not read from address");
        buf.truncate(n);
        // println!("recieved {} bytes from {}", n, &src_addr);

        if src_addr == wgsrv_addr {
            // println!("wg server sent this! forwarded to remote client");
            if let Some(dst) = client_addr {
                //encrypt
                let msg = aes.encrypt(counter, &mut buf);
                socket
                    .send_to(msg, dst)
                    .await
                    .expect("could not write to client");
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
                Err(_) => continue,
            };
            socket
                .send_to(&msg[..], wgsrv_addr)
                .await
                .expect("could not write to wg server");
            // println!("forwarded to wg server")
        }
    }
}
