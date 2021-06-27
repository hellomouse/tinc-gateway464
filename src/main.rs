extern crate nfqueue;
extern crate libc;
extern crate etherparse;

mod state;
mod slice;
mod queue;

use crate::state::{State, Config};
use crate::queue::queue_callback;

fn main() {
    let yaml_config = std::fs::File::open("config.yaml").expect("Config file missing.");
    let config: Config = serde_yaml::from_reader(yaml_config).expect("Invalid config.");

    let queueid = config.nfqueue;

    let mut queue = nfqueue::Queue::new(State::new(config));

    queue.open();
    queue.unbind(libc::AF_INET); // ignore result, failure is not critical here
    queue.unbind(libc::AF_INET6);

    let rc = queue.bind(libc::AF_INET);
    assert!(rc == 0);
    let rc = queue.bind(libc::AF_INET6);
    assert!(rc == 0);

    queue.create_queue(queueid, queue_callback);
    queue.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

    println!("Initialized gateway.");

    queue.run_loop();

    queue.close();

    println!("Terminated gateway.")
}
