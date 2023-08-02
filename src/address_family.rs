use super::MDNS_PORT;
#[cfg(feature = "if-addrs")]
use if_addrs::get_if_addrs;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use sys::if_nametoindex;

pub enum Inet {}

pub enum Inet6 {}

pub trait AddressFamily {
    type Addr: Into<IpAddr>;

    const ANY_ADDR: Self::Addr;
    const MDNS_GROUP: Self::Addr;

    const DOMAIN: Domain;

    fn join_multicast(socket: &Socket, multiaddr: &Self::Addr, #[cfg(not(feature = "if-addrs"))] self_ip: Option<Self::Addr>) -> io::Result<()>;

    fn udp_socket() -> io::Result<Socket> {
        Socket::new(Self::DOMAIN, Type::DGRAM, Some(Protocol::UDP))
    }

    fn bind(#[cfg(not(feature = "if-addrs"))] self_ip: Option<Self::Addr>) -> io::Result<UdpSocket> {
        let addr: SockAddr = SocketAddr::new(Self::ANY_ADDR.into(), MDNS_PORT).into();
        let socket = Self::udp_socket()?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        #[cfg(not(windows))]
        #[cfg(not(target_os = "illumos"))]
        socket.set_reuse_port(true)?;

        socket.bind(&addr)?;
        #[cfg(not(feature = "if-addrs"))]
        Self::join_multicast(&socket, &Self::MDNS_GROUP, self_ip)?;
        #[cfg(feature = "if-addrs")]
        Self::join_multicast(&socket, &Self::MDNS_GROUP)?;
        Ok(socket.into())
    }
}

impl AddressFamily for Inet {
    type Addr = Ipv4Addr;

    const ANY_ADDR: Self::Addr = Ipv4Addr::UNSPECIFIED;
    const MDNS_GROUP: Self::Addr = Ipv4Addr::new(224, 0, 0, 251);

    const DOMAIN: Domain = Domain::IPV4;

    fn join_multicast(socket: &Socket, multiaddr: &Self::Addr, #[cfg(not(feature = "if-addrs"))] self_ip: Option<Self::Addr>) -> io::Result<()> {
        #[cfg(feature = "if-addrs")]
        let addresses = get_address_list()?;
        #[cfg(not(feature = "if-addrs"))]
        let addresses = vec![ self_ip.ok_or(io::Error::new(io::ErrorKind::Other, "no self address specified"))? ];
        if addresses.is_empty() {
            socket.join_multicast_v4(multiaddr, &Ipv4Addr::UNSPECIFIED)
        } else {
            for (_, address) in addresses {
                if let IpAddr::V4(ip) = address {
                    socket.join_multicast_v4(multiaddr, &ip)?;
                }
            }
            Ok(())
        }
    }
}

impl AddressFamily for Inet6 {
    type Addr = Ipv6Addr;

    const ANY_ADDR: Self::Addr = Ipv6Addr::UNSPECIFIED;
    const MDNS_GROUP: Self::Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    const DOMAIN: Domain = Domain::IPV6;

    fn join_multicast(socket: &Socket, multiaddr: &Self::Addr, #[cfg(not(feature = "if-addrs"))] self_ip: Option<Self::Addr>) -> io::Result<()> {
        #[cfg(feature = "if-addrs")]
        let addresses = get_address_list()?;
        #[cfg(not(feature = "if-addrs"))]
        let addresses = vec![ self_ip.ok_or(io::Error::new(io::ErrorKind::Other, "no self address specified"))? ];
        if addresses.is_empty() {
            socket.join_multicast_v6(multiaddr, 0)
        } else {
            // We join multicast by interface, but each interface can have more than one ipv6 address.
            // So we have to check we're not registering more than once, as the resulting error is then
            // fatal to ipv6 listening.
            // TODO: Make each interface resilient to failures on another.
            let mut registered = Vec::new();
            for (iface_name, address) in addresses {
                if let IpAddr::V6(_) = address {
                    let ipv6_index = if_nametoindex(iface_name.as_str()).unwrap_or(0);
                    if ipv6_index != 0 && !registered.contains(&ipv6_index) {
                        socket.join_multicast_v6(multiaddr, ipv6_index)?;
                        registered.push(ipv6_index);
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "if-addrs")]
fn get_address_list() -> io::Result<Vec<(String, IpAddr)>> {
    Ok(get_if_addrs()?
        .iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| (iface.name.clone(), iface.ip()))
        .collect())
}

mod sys {
    use std::ffi::CString;
    #[cfg(windows)]
    use winapi::shared::netioapi;

    pub fn if_nametoindex(ifname: &str) -> Option<u32> {
        let c_str = CString::new(ifname).ok()?;

        #[cfg(not(windows))]
        return Some(unsafe { libc::if_nametoindex(c_str.as_ptr()) });
        #[cfg(windows)]
        return Some(unsafe { netioapi::if_nametoindex(cstr.as_ptr()) });
    }
}
