use aes_gcm::aead::heapless;
use clap::{self, Args, Parser, Subcommand};
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

use udp_obfs::aes::{AES, BUFSIZE, KEYLEN, NONCELEN};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
struct Cli {
    #[command(subcommand)]
    mode: Modes,
}

#[derive(Subcommand, Debug)]
enum Modes {
    Client(ModeArgs),
    Server(ModeArgs),
}

// Ensure secret is correct size
fn secret_enforce_len(s: &str) -> clap::error::Result<String, String> {
    // Compare byte lengths
    if s.len() == KEYLEN {
        Ok(String::from(s))
    } else {
        Err(format!("secret must be {} bytes in length", KEYLEN))
    }
}

#[derive(Args, Debug)]
#[clap(disable_help_flag = true)]
struct ModeArgs {
    #[arg(short, help = "listen host", default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(short, help = "listen port")]
    port: u16,

    #[arg(
        long = "src-host",
        help = "source host (sent decrypted data)",
        default_value = "127.0.0.1"
    )]
    source_host: IpAddr,

    #[arg(long = "src-port", help = "source port (sent decrypted data)")]
    source_port: u16,

    #[arg(
        long = "fwd-host",
        help = "forward host (sent encrypted data)",
        default_value = "127.0.0.1"
    )]
    forward_host: IpAddr,

    #[arg(long = "fwd-port", help = "forward port (sent encrypted data)")]
    forward_port: u16,

    #[arg(short, help = format!("secret encrypt/decrypt key ({} bytes)", KEYLEN), value_parser = secret_enforce_len)]
    secret: String,

    #[arg(long, action = clap::ArgAction::Help)]
    help: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.mode {
        Modes::Client(args) => client(args).await,
        Modes::Server(args) => server(args).await,
    }
}

async fn client(args: &ModeArgs) -> Result<()> {
    let socket = UdpSocket::bind((args.host, args.port))
        .await
        .expect("could not bind to address");
    println!("listening on {}", socket.local_addr()?);

    let proxy_source_addr = SocketAddr::new(args.source_host, args.source_port);
    let proxy_forward_addr = SocketAddr::new(args.forward_host, args.forward_port);

    println!("proxy source addr: {}", proxy_source_addr);
    println!("proxy forward addr: {}", proxy_forward_addr);

    let aes = AES::new(args.secret.as_bytes());

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
    let mut counter = 0u64;

    loop {
        buf.resize(BUFSIZE, 0).unwrap();
        let (n, src_addr) = socket
            .recv_from(&mut buf[..])
            .await
            .expect("could not read from address");
        buf.truncate(n);

        let dst_addr: SocketAddr;
        let msg: &[u8];
        if src_addr == proxy_source_addr {
            msg = aes.encrypt(counter, &mut buf);
            counter = if counter == u64::MAX { 0 } else { counter + 1 };
            dst_addr = proxy_forward_addr;
        } else if src_addr == proxy_forward_addr && n >= NONCELEN {
            msg = match aes.decrypt(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            dst_addr = proxy_source_addr;
        } else {
            continue;
        }

        socket
            .send_to(msg, dst_addr)
            .await
            .expect(format!("could not write to {}", dst_addr).as_str());

        buf.clear();
    }
}

async fn server(args: &ModeArgs) -> Result<()> {
    let socket = UdpSocket::bind((args.host, args.port))
        .await
        .expect("could not bind to address");
    println!("listening on {}", socket.local_addr()?);

    let proxy_source_addr = SocketAddr::new(args.source_host, args.source_port);
    let proxy_forward_addr = SocketAddr::new(args.forward_host, args.forward_port);

    println!("proxy source addr: {}", proxy_source_addr);
    println!("proxy forward addr: {}", proxy_forward_addr);

    let aes = AES::new(args.secret.as_bytes());

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
    let mut counter = 0u64;

    loop {
        buf.resize(BUFSIZE, 0).unwrap();
        let (n, src_addr) = socket
            .recv_from(&mut buf[..])
            .await
            .expect("could not read from address");
        buf.truncate(n);

        let dst_addr: SocketAddr;
        let msg: &[u8];
        if src_addr == proxy_source_addr {
            msg = aes.encrypt(counter, &mut buf);
            counter = if counter == u64::MAX { 0 } else { counter + 1 };
            dst_addr = proxy_forward_addr;
        } else if n >= NONCELEN {
            msg = match aes.decrypt(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            dst_addr = proxy_source_addr;
        } else {
            continue;
        }

        socket
            .send_to(msg, dst_addr)
            .await
            .expect(format!("could not write to {}", dst_addr).as_str());
    }
}
