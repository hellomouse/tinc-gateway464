use etherparse::{TransportSlice, TransportHeader};

pub trait HeaderSlice {
    fn destination_port(&self) -> u16;
    fn source_port(&self) -> u16;
    fn to_header(&self) -> TransportHeader;
}

impl HeaderSlice for TransportSlice<'_> {
    fn source_port(&self) -> u16 {
        match self {
            TransportSlice::Tcp(hs) => hs.source_port(),
            TransportSlice::Udp(hs) => hs.source_port()
        }
    }

    fn destination_port(&self) -> u16 {
        match self {
            TransportSlice::Tcp(hs) => hs.destination_port(),
            TransportSlice::Udp(hs) => hs.destination_port()
        }
    }

    fn to_header(&self) -> TransportHeader {
        match self {
            TransportSlice::Tcp(hs) => TransportHeader::Tcp(hs.to_header()),
            TransportSlice::Udp(hs) => TransportHeader::Udp(hs.to_header())
        }
    }
}
