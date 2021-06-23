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

            if let Some(InternetSlice::Ipv4(ipv4_header)) = packet.ip {
                let dest_ip = format!("{}", ipv4_header.destination_addr());
                let source_ip = ipv4_header.source_addr();

                if let Some(target) = state.config.mappings.get(&dest_ip) {
                    let tslice: TransportSlice = packet.transport.expect("Unexpected transport.");

                    let dport = tslice.destination_port();

                    if let Some(redirection) = target.ports.get(&dport) {
                        let sport = redirection.port;

                        let source6: [u8; 16] = {
                            let [a,b,c,d,e,f] = state.config.base;
                            let [g,h]         = target.reverse;
                            let [i,j,k,l]     = state.config.magic;
                            let [m,n,o,p]     = ipv4_header.source_addr().octets();
                            [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p]
                        };

                        let dest6: [u8; 16] = {
                            let [a,b,c,d,e,f] = state.config.base;
                            let [g,h,i,j,k,l,m,n,o,p] = redirection.addr;
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
                    }
                }
            } else {
                eprintln!("Invalid IPv4 Packet {:?}", packet);
            }
        },
        Err(err) => {
            eprintln!("Packet failed to decode. Packet = {:?}. Error = {:?}", msg.get_payload(), err);
        },
    };

    println!("count: {:?}", state.count);
}
