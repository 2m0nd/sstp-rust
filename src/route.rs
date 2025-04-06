use std::io;
use std::process::Command;

pub fn set_default_route_utun9() -> io::Result<()> {
    println!("🟢 Adding default IPv4 route via utun9 using system command...");
    let status = Command::new("/sbin/route")
        .args(["-n", "add", "-inet", "default", "-interface", "utun9"])
        .status()?;

    if status.success() {
        println!("✅ Default route added via utun9!");
        Ok(())
    } else {
        eprintln!("⚠️ Route add failed — might already exist.");
        Err(io::Error::new(io::ErrorKind::Other, format!("Route command failed with status: {}", status)))
    }
}

fn get_utun_index(name: &str) -> io::Result<u16> {
    use std::ffi::CString;
    let name = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name"))?;
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx as u16)
    }
}