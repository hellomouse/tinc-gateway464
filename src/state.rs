use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PortMap {
    pub port: u16,
    pub addr: [u8; 10]
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AddrMap {
    pub reverse: [u8; 2],
    pub ports: HashMap<u16, PortMap>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub base: [u8; 6],
    pub magic: [u8; 4],
    pub v4queue: u16,
    pub v6queue: u16,
    pub mappings: HashMap<String, AddrMap>,
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
