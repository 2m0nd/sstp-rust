# SSTP Rust Client

This is a Rust-based implementation of an SSTP (Secure Socket Tunneling Protocol) client. It is designed to establish a secure VPN connection using SSTP and manage network traffic through a TUN interface.

## Features

- **SSTP Protocol Support**: Implements the SSTP protocol for secure communication. [docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/c50ed240-56f3-4309-8e0c-1644898f0ea8)
- **TUN Interface Management**: Creates and configures TUN interfaces for routing traffic.
- **PPP State Machine**: Handles the PPP (Point-to-Point Protocol) negotiation process.
- **DHCP Support**: Sends DHCP INFORM requests to retrieve network configuration.
- **TLS Support**: Uses `tokio-rustls` for secure TLS connections.
- **Cross-Platform**: Supports macOS and Linux (with platform-specific implementations).

## Requirements

- **Rust**: Ensure you have Rust installed. You can install it from [rustup.rs](https://rustup.rs/).
- **Dependencies**: The project uses several Rust crates, which are listed in the `Cargo.toml` file.

### Linux-Specific Requirements

- `iproute2`: Required for configuring TUN interfaces.
- Root privileges: Required to create and manage TUN interfaces.

### macOS-Specific Requirements

- `ifconfig`: Used to configure the TUN interface.
- Root privileges: Required to create and manage TUN interfaces.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/sstp-rust.git
   cd sstp-rust
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

   Binaries will be located in `./target/release/sstp-rust`.

3. Configure the environment:
   - Add a `.env` file and use the command:
     ```bash
     sstp-rust useEnv
     ```
     Example `.env` file:
     ```
     SSTP_SERVER=ip_sst_serber
     SSTP_USER=grou\\user
     SSTP_PASSWORD=secret
     ```

   - Alternatively, use the inline command:
     ```bash
     sstp-rust useInline server_ip group\\user secret
     ```

## License

This project is licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.