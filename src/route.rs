use std::net::Ipv4Addr;
use std::process::Command;

pub fn config_routes(vpn_server: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>>   {

    // добавить роут до vpn server'a чере маршрутизатор
    //sudo route add -host SSTP_SERVER 192.168.1.1
    let status = Command::new("route")
    .args([
       "add",
        "-host",
        &vpn_server.to_string(),
        "192.168.1.1"
    ])
    .status()?;
   if !status.success() {
       return Err("add route failed to configure utun".into());
   }
   //sudo route -n delete -net default
    let status = Command::new("route")
    .args([
       "-n",
        "delete",
        "-net",
        "default"
    ])
    .status()?;
   if !status.success() {
       return Err("error remove default route".into());
   }
   Ok(())
}

pub fn restore_default_route() -> Result<(), Box<dyn std::error::Error>>   {

    let status = Command::new("route")
    .args([
       "-n",
        "delete",
        "-net",
        "default"
    ])
    .status()?;
   if !status.success() {
       return Err("error remove default route".into());
   }

    // добавить дефолтный роут через wifi
    //sudo route -n add -net default -interface en0
    let status = Command::new("ifconfig")
    .args([
        "en0",
        "down"
    ])
    .status()?;
   if !status.success() {
       return Err("add route failed to configure utun".into());
   }

   let status = Command::new("ifconfig")
   .args([
       "en0",
       "up"
   ])
   .status()?;
  if !status.success() {
      return Err("add route failed to configure utun".into());
  }
   Ok(())
}