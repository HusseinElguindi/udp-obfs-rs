# udp-obfs-rs
An encrypted UDP tunnel to hide datagram data over the Internet. This project is a demonstration of avoiding Deep Packet Inspection (DPI) by obfuscation.

`udp-obfs-rs` works a layer above a standard WireGuard VPN, encrypting/obfuscating packets before they are sent over the wire, and decrypting received packets before WireGuard handles them. As a result, WireGuard traffic (and, consequently, your routed traffic) cannot be easily inspected by anything in between.

```
+--Client--------------+           +--Server--------------+ 
|  +----------------+  |           |  +----------------+  |
|  |  udp-obfs-rs   |--+-----------+->|  udp-obfs-rs   |  |
|  |  client        |  | encrypted |  |  server        |  |
|  |                |<-+-----------+--|                |  |
|  +---------+------+  |           |  +---------+------+  |
|         ^  |         |           |         ^  |         |
|         |  |         |           |         |  |         |
|         |  v         |           |         |  v         |
|  +------+---------+  |           |  +------+---------+  |
|->|                |  |           |  |                |->|
|  |  WireGuard     |  |           |  |  WireGuard     |  |
|<-|                |  |           |  |                |<-|
|  +----------------+  |           |  +----------------+  |
+----------------------+           +----------------------+
```

## Usage
```bash
Usage: udp-obfs-rs (client|server) [OPTIONS] -p <PORT> --src <SOURCE_SOCKET> --fwd <FORWARD_SOCKET> -s <SECRET>

Options:
  -h <HOST>                   listen host [default: 0.0.0.0]
  -p <PORT>                   listen port
      --src <SOURCE_SOCKET>   source socket (sends/receives decrypted data)
      --fwd <FORWARD_SOCKET>  forward socket (sends/receives encrypted data)
  -s <SECRET>                 secret encrypt/decrypt key (16 bytes)
      --help
```

### Tunnelling WireGuard Traffic
The listen host and listen port is the socket which receives unencrypted data to then be forwarded (after its encryption) to the remote client. As such, this is usually the same value as the peer endpoint in the local WireGuard config.

The `SOURCE_SOCKET` is the socket that sends to the listen host/port, it also receives decrypted traffic from the remote client. The port should be the same value as the `ListenPort` field in our local WireGuard config (the host can just be `127.0.0.1`).

The `FORWARD_SOCKET` is the (usually remote) socket that receives encrypted traffic, it is another instance of this program. As such, this value is the remote address of the remote client; the port is the same port set in the listen port for the remote instance of this program. 

The `SECRET` is a 16 byte (because of AES 128) key used to encrypt/decrypt the UDP datagram content.

For server configuration details and more information, read [this article](https://elguindi.xyz/post/vpn-udp-tunnel).
