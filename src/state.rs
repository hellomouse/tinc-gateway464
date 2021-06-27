use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct AddrMap {
    pub reverse: [u8; 2],
    pub ports: HashMap<u16, Ipv6Addr>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Config {
    pub base: [u8; 6],
    pub magic: [u8; 4],
    pub nfqueue: u16,
    pub mappings: HashMap<Ipv4Addr, AddrMap>,
}

pub struct State {
    pub count: u32,
    pub forwarded: u32,
    pub config: Config
}

impl State {
    pub fn new(config: Config) -> State {
        State { count: 0, forwarded: 0, config }
    }
}
