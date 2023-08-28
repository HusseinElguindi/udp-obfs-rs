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
    // Commonly the local WireGaurd "Peer Endpoint" host
    #[arg(short, help = "listen host", default_value = "0.0.0.0")]
    host: IpAddr,

    // Commonly the local WireGaurd "Peer Endpoint" port
    #[arg(short, help = "listen port")]
    port: u16,

    // Commonly the local WireGuard socket address
    #[arg(long = "src", help = "source socket (sends/receives decrypted data)")]
    source_socket: SocketAddr,

    // Commonly the remote proxy socket address
    #[arg(long = "fwd", help = "forward socket (sends/receives encrypted data)")]
    forward_socket: SocketAddr,

    #[arg(short, help = format!("secret encrypt/decrypt key ({} bytes)", KEYLEN), value_parser = secret_enforce_len)]
    secret: String,

    // Disable `-h` for help
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

    let proxy_source_addr = args.source_socket;
    let proxy_forward_addr = args.forward_socket;

    println!("proxy source address: {}", proxy_source_addr);
    println!("proxy forward address: {}", proxy_forward_addr);

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

    let proxy_source_addr = args.source_socket;
    let proxy_forward_addr = args.forward_socket;

    println!("proxy source address: {}", proxy_source_addr);
    println!("proxy forward address: {}", proxy_forward_addr);

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
