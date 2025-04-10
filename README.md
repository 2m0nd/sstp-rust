Build cargo build --release

Binaries will be there -> ./target/release/sstp-rust

Add .env and use command "sstp-rust useEnv"

SSTP_SERVER=ip_sst_serber
SSTP_USER=grou\\user
SSTP_PASSWORD=secret

Or use command "sstp-rust useInline server_ip group\\user secret"