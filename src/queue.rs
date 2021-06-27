use etherparse::{SlicedPacket, InternetSlice};
use etherparse::{SerializedSize, Ipv4Header, Ipv6Header};
use nfqueue::{Message, Verdict};
use pnet_sys::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, SocketAddrV4};
use std::convert::TryInto;

use crate::state::State;
use crate::slice::HeaderSlice;

pub fn queue_callback(msg: &Message, state: &mut State) {
    // println!("Packet received [id: 0x{:x}]\n", msg.get_id());

    state.count += 1;
    // println!("count: {:?}", state.count);

    match SlicedPacket::from_ip(msg.get_payload()) {
        Ok(packet) => {
            // println!("{:?}", packet);

            match packet.ip {
                Some(InternetSlice::Ipv4(ipv4_header)) => {
                    let dest_ip = format!("{}", ipv4_header.destination_addr());
                    let source_ip = ipv4_header.source_addr();

                    if let Some(target) = state.config.mappings.get(&ipv4_header.destination_addr()) {
                        let tslice = packet.transport.expect("Unexpected transport.");

                        let dport = tslice.destination_port();
                        if let Some(redirection) = target.ports.get(&dport) {
                            msg.set_verdict(Verdict::Drop);

                            let source6: [u8; 16] = {
                                let [a,b,c,d,e,f] = state.config.base;
                                let [g,h]         = target.reverse;
                                let [i,j,k,l]     = state.config.magic;
                                let [m,n,o,p]     = ipv4_header.source_addr().octets();
                                [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p]
                            };

                            let dest6: [u8; 16] = redirection.octets();

                            let mut packet6 = Vec::<u8>::with_capacity(
                                Ipv6Header::SERIALIZED_SIZE
                                - Ipv4Header::SERIALIZED_SIZE
                                + (ipv4_header.total_len() as usize)
                            );

                            let header6 = Ipv6Header {
                                traffic_class: 0,
                                flow_label: 0,
                                payload_length: ipv4_header.payload_len(),
                                next_header: ipv4_header.protocol(),
                                hop_limit: ipv4_header.ttl(),
                                source: source6,
                                destination: dest6
                            };

                            header6.write(&mut packet6).unwrap();

                            let theader = {
                                let mut th = tslice.to_header();
                                th.update_checksum_ipv6(&header6, packet.payload).unwrap();
                                th
                            };

                            theader.write(&mut packet6).unwrap();

                            packet6.extend_from_slice(packet.payload);

                            let source6 = Ipv6Addr::from(source6);
                            let dest6 = Ipv6Addr::from(dest6);

                            println!("Forwarding packet {:?}:{:?} => {:?}:{:?}", source_ip, tslice, dest_ip, dport);
                            println!("Now is {:?} => {:?}", source6, dest6);
                            println!("New packet is {:?}", packet6);
                            
                            // pnet does not support Layer3 IPv6
                            // The following blocks were copied from the pnet library
                            let sock = unsafe {
                                // 255 = IPPROTO_RAW
                                socket(AF_INET6, SOCK_RAW, 255)
                            };
                            if sock == INVALID_SOCKET {
                                return;
                            };
                            let mut caddr = unsafe { std::mem::zeroed() };
                            let sockaddr = SocketAddr::V6(SocketAddrV6::new(dest6, 0, 0, 0));
                            let slen = pnet_sys::addr_to_sockaddr(sockaddr, &mut caddr);
                            let caddr_ptr = (&caddr as *const pnet_sys::SockAddrStorage) as *const pnet_sys::SockAddr;
                            println!("Send status: {:?}", send_to(sock, &packet6, caddr_ptr, slen));
                            
                            state.forwarded += 1;
                            return;
                     }
                   }
                },
                Some(InternetSlice::Ipv6(ipv6_header, _)) => {
                    if let None = packet.transport {
                        return;
                    }
                    let tslice = packet.transport.expect("Unexpected transport.");
                    let sport = tslice.source_port();
                    println!("Got v6 packet! from {:?}", ipv6_header.destination_addr());
                    for (v4source, map) in &state.config.mappings {
                        for (port, _) in &map.ports {
                            if port != &sport {
                                continue; // Not even the correct port
                            }
                            let dest_addr: [u8; 16] = ipv6_header.destination_addr().octets();
                            if dest_addr[0..6] != state.config.base {
                                continue; // Not the correct daemon
                            }
                            if dest_addr[6..8] != map.reverse {
                                continue; // Not the correct reverse
                            }
                            if dest_addr[8..12] != state.config.magic {
                                continue; // Not the correct magic value
                            }
                            msg.set_verdict(Verdict::Drop);
                            let destination = dest_addr[12..16].try_into().unwrap();
                            let mut header4 = Ipv4Header::new(
                                ipv6_header.payload_length(),
                                ipv6_header.hop_limit(),
                                etherparse::IpTrafficClass::Udp, // DUMMY
                                v4source.octets(),
                                destination
                            );
                            header4.protocol = ipv6_header.next_header();

                            let mut packet4 = Vec::<u8>::with_capacity(
                                Ipv4Header::SERIALIZED_SIZE
                                + (ipv6_header.payload_length() as usize)
                            );
                            header4.write(&mut packet4).unwrap();
                            let theader = {
                                let mut th = tslice.to_header();
                                th.update_checksum_ipv4(&header4, packet.payload).unwrap();
                                th
                            };

                            theader.write(&mut packet4).unwrap();
                            packet4.extend_from_slice(packet.payload);
                            println!("New packet is {:?}", packet4);

                            let sock = unsafe {
                                // 255 = IPPROTO_RAW
                                socket(AF_INET, SOCK_RAW, 255)
                            };
                            if sock == INVALID_SOCKET {
                                return;
                            };
                            let mut caddr = unsafe { std::mem::zeroed() };
                            let sockaddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(destination), 0));
                            let slen = pnet_sys::addr_to_sockaddr(sockaddr, &mut caddr);
                            let caddr_ptr = (&caddr as *const pnet_sys::SockAddrStorage) as *const pnet_sys::SockAddr;
                            println!("Send status: {:?}", send_to(sock, &packet4, caddr_ptr, slen));
                            
                            state.forwarded += 1;
                            return;
                        }
                    }
                },
                _ => {
                    eprintln!("Unrecognized packet type {:?}", packet);
                }
            }
        },
        Err(err) => {
            eprintln!("Packet failed to decode. Packet = {:?}. Error = {:?}", msg.get_payload(), err);
        },
    };
    // println!("Packet ignored.");
    msg.set_verdict(Verdict::Accept);
}
