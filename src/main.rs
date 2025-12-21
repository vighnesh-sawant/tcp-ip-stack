use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use etherparse::{
    ArpHardwareId, ArpOperation, ArpPacket, ArpPacketSlice, EtherType, Ethernet2Slice,
    PacketBuilder,
};
use mac_address::mac_address_by_name;
use tappers::{Interface, Tap};
type MacAddr = [u8; 6];
type IpAddr = [u8; 4];
fn main() {
    let tap_name = Interface::new("tap0").unwrap();
    let mut tap = Tap::new_named(tap_name).unwrap();
    tap.set_up().unwrap();
    let mut recv_buf = [0; 1514];
    let mut arp_table: Arc<RwLock<DashMap<IpAddr, MacAddr>>> =
        Arc::new(RwLock::new(DashMap::new()));
    loop {
        tap.recv(&mut recv_buf).unwrap();
        handle_frame(&recv_buf, &mut arp_table, &mut tap);
    }
}

fn handle_frame(buf: &[u8], arp_table: &mut Arc<RwLock<DashMap<IpAddr, MacAddr>>>, tap: &mut Tap) {
    let frame = Ethernet2Slice::from_slice_without_fcs(buf).unwrap();
    match frame.ether_type() {
        EtherType::ARP => handle_arp(frame.payload_slice(), arp_table, tap),
        _ => println!("Aint handling this yet"),
    }
}
#[allow(clippy::collapsible_if)]
fn handle_arp(buf: &[u8], arp_table: &mut Arc<RwLock<DashMap<IpAddr, MacAddr>>>, tap: &mut Tap) {
    let packet = ArpPacketSlice::from_slice(buf).unwrap();

    if packet.hw_addr_type() == ArpHardwareId::ETHERNET {
        if packet.proto_addr_type() == EtherType::IPV4 {
            let table = arp_table.write().unwrap();
            table.insert(
                packet.sender_protocol_addr().try_into().unwrap(),
                packet.sender_hw_addr().try_into().unwrap(),
            );
            let myip: [u8; 4] = [10, 0, 0, 4];
            let mymac = mac_address_by_name("tap0").unwrap().unwrap().bytes();
            if packet.target_protocol_addr() == myip {
                if packet.operation() == ArpOperation::REQUEST {
                    let reply = ArpPacket::new(
                        ArpHardwareId::ETHERNET,
                        EtherType::IPV4,
                        ArpOperation::REPLY,
                        &mymac,
                        packet.target_protocol_addr(),
                        packet.sender_hw_addr(),
                        packet.sender_protocol_addr(),
                    )
                    .unwrap();

                    let builder = PacketBuilder::ethernet2(
                        reply.sender_hw_addr().try_into().unwrap(),
                        reply.target_hw_addr().try_into().unwrap(),
                    )
                    .arp(reply);
                    let mut result = Vec::<u8>::with_capacity(builder.size());
                    builder.write(&mut result).unwrap();
                    tap.send(&result).unwrap();
                }
            }
        }
    }
}
