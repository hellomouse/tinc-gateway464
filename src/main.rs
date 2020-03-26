extern crate nfqueue;
extern crate libc;
extern crate etherparse;
use etherparse::*;
use serde::{Serialize, Deserialize};
use std::fs;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PortMap {
    port: u16,
    addr: [u8; 10]
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct AddrMap {
    reverse: [u8; 2],
    ports: HashMap<u16, PortMap>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    base: [u8; 6],
    magic: [u8; 4],
    v4queue: u16,
    v6queue: u16,
    mappings: HashMap<String, AddrMap>,
}

struct State {
    count: u32,
    forwarded: u32,
    config: Config
}

impl State {
    pub fn new(config: Config) -> State {
        State { count: 0, forwarded: 0, config }
    }
}

fn queue_callback_v4(msg: &nfqueue::Message, state: &mut State) {
    println!("Packet received [id: 0x{:x}]\n", msg.get_id());

    msg.set_verdict(nfqueue::Verdict::Accept);
    state.count += 1;

    match SlicedPacket::from_ip(msg.get_payload()) {
        Ok(packet) => {
            println!("{:?}", packet);

            match packet.ip {
                Some(InternetSlice::Ipv4(ip)) => {
                    let dest_ip = format!("{}", ip.destination_addr());
                    let source_ip = ip.source_addr();

                    if let Some(target) = state.config.mappings.get(&dest_ip) {
                        let (dport, transheader): (Option<u16>, Option<TransportSlice>) = match packet.transport {
                            Some(TransportSlice::Tcp(info)) => {
                                (Some(info.destination_port()), Some(TransportSlice::Tcp(info)))
                            },
                            Some(TransportSlice::Udp(info)) => {
                                (Some(info.destination_port()), Some(TransportSlice::Udp(info)))
                            },
                            _ => (None, None) // No port = no forwarding possible.
                        };
                        if let Some(dport) = dport {
                            if let Some(redirection) = target.ports.get(&dport) {
                                let sport = redirection.port;
                                let source6: [u8; 16] = {
                                    let [a,b,c,d,e,f] = state.config.base;
                                    let [g,h]         = target.reverse;
                                    let [i,j,k,l]     =  state.config.magic;
                                    let [m,n,o,p]     =  ip.source_addr().octets();
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
                                    + (ip.total_len() as usize));
                                let v6header = Ipv6Header {
                                    traffic_class: 0,
                                    flow_label: 0,
                                    payload_length: ip.payload_len(),
                                    next_header: ip.protocol(),
                                    hop_limit: ip.ttl(),
                                    source: source6,
                                    destination: dest6
                                };
                                v6header.write(&mut packet6).unwrap();
                                match transheader {
                                    Some(TransportSlice::Tcp(info)) => {
                                        let mut info = info.to_header();
                                        info.checksum = info.calc_checksum_ipv6(&v6header, packet.payload).unwrap();
                                        info.write(&mut packet6).unwrap();
                                    }
                                    Some(TransportSlice::Udp(info)) => {
                                        let info = info.to_header();
                                        UdpHeader::with_ipv6_checksum(
                                            info.source_port,
                                            info.destination_port,
                                            &v6header,
                                            packet.payload
                                        ).unwrap().write(&mut packet6).unwrap();
                                    },
                                    _ => panic!("Unexpected transport.")
                                }
                                packet6.extend_from_slice(packet.payload);
                                println!("Forwarding packet {:?}:{:?} => {:?}:{:?}", source_ip, sport, dest_ip, dport);
                                println!("Now is {:?} => {:?}", source6, dest6);
                                println!("New packet is {:?}", packet6);
                                state.forwarded += 1;
                                msg.set_verdict(nfqueue::Verdict::Drop);
                            }
                        }
                    }
                }
                _ => {
                    println!("Invalid IPv4 Packet {:?}", packet);
                }
            }
        }
        Err(err) => {
            println!("Packet failed to decode. Packet = {:?}. Error = {:?}", msg.get_payload(), err);
        }
    }
    println!("count: {:?}", state.count);
}

fn main() {
    let yaml_config = fs::read_to_string("config.example.yaml").expect("Config file missing.");
    let config: Config = serde_yaml::from_str(&yaml_config).expect("Invalid config.");
    let v4queueid = config.v4queue;

    let mut v4queue = nfqueue::Queue::new(State::new(config));
    v4queue.open();
    v4queue.unbind(libc::AF_INET); // ignore result, failure is not critical here
    let rc = v4queue.bind(libc::AF_INET);
    assert!(rc == 0);
    v4queue.create_queue(v4queueid, queue_callback_v4);
    v4queue.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

    println!("Initialized gateway.");

    v4queue.run_loop();

    v4queue.close();
    println!("Terminated gateway.")
}
