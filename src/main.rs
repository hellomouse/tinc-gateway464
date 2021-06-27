extern crate nfqueue;
extern crate libc;
extern crate etherparse;

mod state;
mod slice;
mod queue;

use crate::state::{State, Config};
use crate::queue::queue_callback_v4;

fn main() {
    let yaml_config = std::fs::File::open("config.example.yaml").expect("Config file missing.");
    let config: Config = serde_yaml::from_reader(yaml_config).expect("Invalid config.");

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
