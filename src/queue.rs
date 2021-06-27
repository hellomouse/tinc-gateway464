use std::net::IpAddr;

use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use etherparse::{SerializedSize, Ipv4Header, Ipv6Header};
use nfqueue::{Message, Verdict};

use crate::state::State;
use crate::slice::HeaderSlice;

pub fn queue_callback_v4(msg: &Message, state: &mut State) {
    println!("Packet received [id: 0x{:x}]\n", msg.get_id());

    msg.set_verdict(Verdict::Accept);
    state.count += 1;

    match SlicedPacket::from_ip(msg.get_payload()) {
        Ok(packet) => {
            println!("{:?}", packet);

            if let Some(header) = packet.ip {
                let (dest_ip, source_ip): (IpAddr, IpAddr) = match &header {
                    InternetSlice::Ipv4(h) => {
                        (IpAddr::V4(h.source_addr()), IpAddr::V4(h.destination_addr()))
                    },
                    InternetSlice::Ipv6(h, _) => {
                        (IpAddr::V6(h.source_addr()), IpAddr::V6(h.destination_addr()))
                    }
                };

                let tslice: TransportSlice = packet.transport.expect("Unexpected transport.");
                let dport = tslice.destination_port();

                if let Some(target) = state.config.mappings.get(&dest_ip.to_string()) {
                    if let Some(redirection) = target.ports.get(&dport) {
                        let sport = redirection.port;

                        let dest6: [u8; 16] = {
                            let [a,b,c,d,e,f] = state.config.base;
                            let [g,h,i,j,k,l,m,n,o,p] = redirection.addr;
                            [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p]
                        };

                        if let InternetSlice::Ipv4(ipv4_header) = header {
                            let source6: [u8; 16] = {
                                let [a,b,c,d,e,f] = state.config.base;
                                let [g,h]         = target.reverse;
                                let [i,j,k,l]     = state.config.magic;
                                let [m,n,o,p]     = ipv4_header.source_addr().octets();
                                [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p]
                            };

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

                            println!("Forwarding packet {:?}:{:?} => {:?}:{:?}", source_ip, sport, dest_ip, dport);
                            println!("Now is {:?} => {:?}", source6, dest6);
                            println!("New packet is {:?}", packet6);

                            state.forwarded += 1;

                            msg.set_verdict(Verdict::Drop);
                        } else {
                            eprintln!("Invalid IPv4 Header {:?}", header);
                        }
                    }
                }
            }
        },
        Err(err) => {
            eprintln!("Packet failed to decode. Packet = {:?}. Error = {:?}", msg.get_payload(), err);
        },
    };

    println!("count: {:?}", state.count);
}
