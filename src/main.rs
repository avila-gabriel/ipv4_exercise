use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, PartialEq)]
struct NetworkInfo {
    ip_address: IpAddr,
    cidr: u8,
    subnet_mask: Ipv4Addr,
    ip_class: char,
    is_private: bool,
    network_address: Ipv4Addr,
    broadcast_address: Option<Ipv4Addr>,
    host_range_start: Option<Ipv4Addr>,
    host_range_end: Option<Ipv4Addr>,
    usable_hosts: u32,
    dhcp_range_start: Option<Ipv4Addr>,
    dhcp_range_end: Option<Ipv4Addr>,
    default_gateway: Option<Ipv4Addr>,
    needs_nat: bool,
}

impl NetworkInfo {
    pub fn analyze_network(ip_address: IpAddr, cidr: u8) -> Self {
        let octets: [u8; 4];
        let ipv4_addr = if let IpAddr::V4(ipv4) = ip_address {
            octets = ipv4.octets();
            ipv4
        } else {
            panic!("Only IPv4 addresses are supported in this implementation.");
        };
        let ip_as_u32 = u32::from(ipv4_addr);

        let is_private = match (octets[0], octets[1]) {
            (10, _) => true,                       // 10.0.0.0/8
            (172, 16..32) => true,                 // 172.16.0.0/12
            (192, 168) => true,                    // 192.168.0.0/16
            _ => false,
        };

        let ip_class = match octets[0] {
            1_u8..128_u8 => 'A',
            128_u8..192_u8 => 'B',
            192_u8..224_u8 => 'C',
            224_u8..240_u8 => 'D',
            _ => 'E',
        };

        let subnet_mask = Ipv4Addr::from(u32::MAX << (32 - cidr));

        let broadcast_address = match ip_class{
                'D' | 'E' => None,
            _ => {
                let mask = u32::MAX << (32 - cidr);
                let broadcast_as_u32 = ip_as_u32 | !mask;
                Some(Ipv4Addr::from(broadcast_as_u32))
            }
        };

        let network_address = {
            let mask = u32::MAX << (32 - cidr);
            let network_as_u32 = ip_as_u32 & mask;
            Ipv4Addr::from(network_as_u32)
        };

        let host_range_start = match cidr {
            31 | 32 => None,
            _ => match ip_class {
                'D' | 'E' => None,
                _ => {
                    let mut octets = network_address.octets();
                    octets[3] += if cidr < 32 { 1 } else { 0 };
                    Some(Ipv4Addr::from(octets))
                }
            }
        };

        let host_range_end = match cidr {
            31 | 32 => None,
            _ => match ip_class {
                'D' | 'E' => None,
                _ => {
                    let mut octets = broadcast_address.unwrap().octets();
                    octets[3] -= if cidr < 32 { 1 } else { 0 };
                    Some(Ipv4Addr::from(octets))
                }
            }
        };

        let usable_hosts = match ip_class {
            'E' | 'D' => 0,
            _ => if cidr > 30 { 0 } else { 2_u32.pow(32_u32 - u32::from(cidr)) - 2 }
        };

        let dhcp_range_start = match cidr {
            31 | 32 => None,
            _ => match ip_class {
                'D' | 'E' => None,
                _ => {
                    let mut octets = host_range_start.unwrap().octets();
                    if cidr < 25 { octets[3] += 9 };
                    Some(Ipv4Addr::from(octets))
                }
            }
        };

        let dhcp_range_end = match cidr {
            31 | 32 => None,
            _ => match ip_class {
                'D' | 'E' => None,
                _ => {
                    let mut octets = dhcp_range_start.unwrap().octets();
                    octets[3] = octets[3].saturating_add(90);
                    Some(Ipv4Addr::from(octets))
                }
            }
        };

        let default_gateway = match cidr {
            31 | 32 => None,
            _ => match ip_class {
                'D' | 'E' => None,
                _ => Some(host_range_start.unwrap())
            }
        };

        let needs_nat = is_private;

        NetworkInfo {
            ip_address,
            cidr,
            subnet_mask,
            ip_class,
            is_private,
            network_address,
            broadcast_address,
            host_range_start,
            host_range_end,
            usable_hosts,
            dhcp_range_start,
            dhcp_range_end,
            default_gateway,
            needs_nat,
        }   
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_class_c_network() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(network_info.ip_class, 'C');
        assert!(network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(192, 168, 1, 255)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(network_info.usable_hosts, 254);
        assert_eq!(network_info.dhcp_range_start, Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(network_info.default_gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(network_info.needs_nat);
    }

    #[test]
    fn test_class_a_network() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(network_info.ip_class, 'A');
        assert!(network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(10, 255, 255, 255)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(10, 255, 255, 254)));
        assert_eq!(network_info.usable_hosts, 16777214);
        assert_eq!(network_info.dhcp_range_start, Some(Ipv4Addr::new(10, 0, 0, 10)));
        assert_eq!(network_info.default_gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(network_info.needs_nat);
    }

    #[test]
    fn test_public_ip_class_b() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0)), 16);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(network_info.ip_class, 'B');
        assert!(!network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(172, 32, 0, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(172, 32, 255, 255)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(172, 32, 0, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(172, 32, 255, 254)));
        assert_eq!(network_info.usable_hosts, 65534);
        assert_eq!(network_info.dhcp_range_start, Some(Ipv4Addr::new(172, 32, 0, 10)));
        assert_eq!(network_info.default_gateway, Some(Ipv4Addr::new(172, 32, 0, 1)));
        assert!(!network_info.needs_nat);
    }

    #[test]
    fn test_smallest_subnet_class_c() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 30);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(network_info.ip_class, 'C');
        assert!(network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(192, 168, 1, 3)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(network_info.usable_hosts, 2);
        assert_eq!(network_info.dhcp_range_start, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(network_info.default_gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(network_info.needs_nat);
    }

    #[test]
    fn test_single_host_subnet() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(network_info.ip_class, 'A');
        assert!(network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(network_info.host_range_start, None);
        assert_eq!(network_info.host_range_end, None);
        assert_eq!(network_info.usable_hosts, 0);
        assert_eq!(network_info.dhcp_range_start, None);
        assert_eq!(network_info.default_gateway, None);
        assert!(network_info.needs_nat);
    }

    #[test]
    fn test_large_class_b_subnet() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 240, 0, 0));
        assert_eq!(network_info.ip_class, 'B');
        assert!(network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(172, 31, 255, 255)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(172, 31, 255, 254)));
        assert_eq!(network_info.usable_hosts, 1048574);
        assert_eq!(network_info.dhcp_range_start, Some(Ipv4Addr::new(172, 16, 0, 10)));
        assert_eq!(network_info.default_gateway, Some(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(network_info.needs_nat);
    }

    #[test]
    fn test_class_d_multicast() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 4);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(240, 0, 0, 0));
        assert_eq!(network_info.ip_class, 'D');
        assert!(!network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(224, 0, 0, 0));
        assert_eq!(network_info.broadcast_address, None);
        assert_eq!(network_info.host_range_start, None);
        assert_eq!(network_info.host_range_end, None);
        assert_eq!(network_info.dhcp_range_start, None);
        assert_eq!(network_info.dhcp_range_end, None);
        assert_eq!(network_info.default_gateway, None);
        assert_eq!(network_info.usable_hosts, 0);
        assert!(!network_info.needs_nat);
    }

    #[test]
    fn test_class_e_experimental() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)), 4);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(240, 0, 0, 0));
        assert_eq!(network_info.ip_class, 'E');
        assert!(!network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(240, 0, 0, 0));
        assert_eq!(network_info.broadcast_address, None);
        assert_eq!(network_info.host_range_start, None);
        assert_eq!(network_info.host_range_end, None);
        assert_eq!(network_info.dhcp_range_start, None);
        assert_eq!(network_info.dhcp_range_end, None);
        assert_eq!(network_info.default_gateway, None);
        assert_eq!(network_info.usable_hosts, 0);
        assert!(!network_info.needs_nat);
    }

    #[test]
    fn test_public_class_b_ip() {
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(130, 10, 0, 0)), 16);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(network_info.ip_class, 'B');
        assert!(!network_info.is_private);
        assert_eq!(network_info.network_address, Ipv4Addr::new(130, 10, 0, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(130, 10, 255, 255)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(130, 10, 0, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(130, 10, 255, 254)));
        assert_eq!(network_info.usable_hosts, 65534);
        assert_eq!(network_info.dhcp_range_start, Some(Ipv4Addr::new(130, 10, 0, 10)));
        assert_eq!(network_info.default_gateway, Some(Ipv4Addr::new(130, 10, 0, 1)));
        assert!(!network_info.needs_nat);
    }
    #[test]
    fn test_cidr_31() {
        // Test a /31 subnet, commonly used for point-to-point links
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 31);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 254));
        assert_eq!(network_info.usable_hosts, 0);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(network_info.host_range_start, None);
        assert_eq!(network_info.host_range_end, None);
        assert_eq!(network_info.dhcp_range_start, None);
        assert_eq!(network_info.default_gateway, None);
    }

    #[test]
    fn test_cidr_32() {
        // Test a /32 subnet, representing a single IP with no host range
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 32);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(network_info.usable_hosts, 0);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(10, 1, 1, 1)));
        assert_eq!(network_info.host_range_start, None);
        assert_eq!(network_info.host_range_end, None);
        assert_eq!(network_info.dhcp_range_start, None);
        assert_eq!(network_info.default_gateway, None);
    }

    #[test]
    fn test_varied_cidr_class_a() {
        // Test Class A with different CIDR values
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 8);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(network_info.usable_hosts, 16777214);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(10, 255, 255, 255)));

        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 16);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(network_info.usable_hosts, 65534);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(10, 10, 255, 255)));
    }

    #[test]
    fn test_varied_cidr_class_b() {
        // Test Class B with CIDR values less than and greater than the default /16
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(172, 16, 10, 10)), 12);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 240, 0, 0));
        assert_eq!(network_info.usable_hosts, 1048574);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(172, 31, 255, 255)));

        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(172, 16, 10, 10)), 24);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(network_info.usable_hosts, 254);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(172, 16, 10, 255)));
    }

    #[test]
    fn test_varied_cidr_class_c() {
        // Test Class C with CIDR values less than and greater than the default /24
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 10)), 20);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 240, 0));
        assert_eq!(network_info.usable_hosts, 4094);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(192, 168, 15, 255)));

        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 10)), 28);
        assert_eq!(network_info.subnet_mask, Ipv4Addr::new(255, 255, 255, 240));
        assert_eq!(network_info.usable_hosts, 14);
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(192, 168, 10, 15)));
    }

    #[test]
    fn test_non_boundary_address() {
        // Test a Class A IP with /16 that doesn't align on a /16 boundary
        let network_info = NetworkInfo::analyze_network(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 16);
        assert_eq!(network_info.network_address, Ipv4Addr::new(10, 10, 0, 0));
        assert_eq!(network_info.broadcast_address, Some(Ipv4Addr::new(10, 10, 255, 255)));
        assert_eq!(network_info.host_range_start, Some(Ipv4Addr::new(10, 10, 0, 1)));
        assert_eq!(network_info.host_range_end, Some(Ipv4Addr::new(10, 10, 255, 254)));
        assert_eq!(network_info.usable_hosts, 65534);
    }
}
