use std::error;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use dashmap::DashMap;

use etherparse::checksum::Sum16BitWords;
use etherparse::{
    ArpHardwareId, ArpOperation, ArpPacket, ArpPacketSlice, EtherType, Ethernet2Slice,
    IcmpEchoHeader, Icmpv4Slice, Icmpv4Type, IpNumber, Ipv4Slice, PacketBuilder,
};

use mac_address::mac_address_by_name;
use tappers::{Interface, Tap};

//too much effort making them structs
type MacAddr = [u8; 6];
type Ip4Addr = [u8; 4];

static MYIP: [u8; 4] = [10, 0, 0, 4];

fn main() {
    let tap_name = Interface::new("tap0").unwrap();
    let mut tap = Tap::new_named(tap_name).unwrap();
    tap.add_addr(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    tap.set_up().unwrap();

    let mut recv_buf = [0; 1514];

    let mut arp_table: Arc<RwLock<DashMap<Ip4Addr, MacAddr>>> =
        Arc::new(RwLock::new(DashMap::new()));

    loop {
        tap.recv(&mut recv_buf).unwrap();
        handle_frame(&recv_buf, &mut arp_table, &mut tap).ok();
    }
}

fn handle_frame(
    buf: &[u8],
    arp_table: &mut Arc<RwLock<DashMap<Ip4Addr, MacAddr>>>,
    tap: &mut Tap,
) -> Result<(), Box<dyn error::Error>> {
    let frame = Ethernet2Slice::from_slice_without_fcs(buf)?;

    match frame.ether_type() {
        EtherType::ARP => handle_arp(frame.payload_slice(), arp_table, tap)?,
        EtherType::IPV4 => handle_ipv4(frame.payload_slice(), arp_table, tap, &frame.source())?,
        _ => println!("Aint handling this yet {:?}", frame.ether_type()),
    }
    Ok(())
}
#[allow(clippy::collapsible_if)] //prefer writing my ifs like this 
fn handle_arp(
    buf: &[u8],
    arp_table: &mut Arc<RwLock<DashMap<Ip4Addr, MacAddr>>>,
    tap: &mut Tap,
) -> Result<(), Box<dyn error::Error>> {
    let packet = ArpPacketSlice::from_slice(buf)?;

    if packet.hw_addr_type() == ArpHardwareId::ETHERNET {
        if packet.proto_addr_type() == EtherType::IPV4 {
            let table = arp_table.write().unwrap(); //arp table corrupted??
            table.insert(
                packet.sender_protocol_addr().try_into()?,
                packet.sender_hw_addr().try_into()?,
            );
            // this causes panic because tap0 is not there how is that possible?
            let mymac = mac_address_by_name("tap0").unwrap().unwrap().bytes();
            if packet.target_protocol_addr() == MYIP {
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
                        reply.sender_hw_addr().try_into()?,
                        reply.target_hw_addr().try_into()?,
                    )
                    .arp(reply);
                    let mut result = Vec::<u8>::with_capacity(builder.size());
                    builder.write(&mut result)?;
                    tap.send(&result)?;
                }
            }
        }
    }
    Ok(())
}

fn handle_ipv4(
    buf: &[u8],
    arp_table: &mut Arc<RwLock<DashMap<Ip4Addr, MacAddr>>>,
    tap: &mut Tap,
    src_mac: &[u8; 6],
) -> Result<(), Box<dyn error::Error>> {
    let packet = Ipv4Slice::from_slice(buf)?;
    let header = packet.header();
    let csm = Sum16BitWords::new().add_slice(header.slice());
    if csm.ones_complement() == 0 {
        if header.destination() == MYIP {
            match header.protocol() {
                //ignoring fragmentation currently
                IpNumber::ICMP => handle_icmpv4(
                    packet.payload().payload,
                    arp_table,
                    tap,
                    header.source(),
                    src_mac,
                )?,
                _ => println!("Aint handling this yet"),
            }
        } else {
            println!("Umm destination address is not equal to ours?? packet dropped");
        }
    } else {
        println!(
            "Ipv4 Header CSM failed, packet dropped {:?}",
            csm.ones_complement()
        );
    }
    Ok(())
}

fn handle_icmpv4(
    buf: &[u8],
    arp_table: &mut Arc<RwLock<DashMap<Ip4Addr, MacAddr>>>,
    tap: &mut Tap,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
) -> Result<(), Box<dyn error::Error>> {
    let packet = Icmpv4Slice::from_slice(buf)?;
    match packet.icmp_type() {
        Icmpv4Type::EchoRequest(icmp_echo_header) => handle_icmpv4_echo_request(
            icmp_echo_header,
            packet.payload(),
            arp_table,
            tap,
            srcip,
            src_mac,
        )?,
        _ => println!("Aint handling this yet"),
    }
    Ok(())
}

fn handle_icmpv4_echo_request(
    header: IcmpEchoHeader,
    payload: &[u8],
    arp_table: &mut Arc<RwLock<DashMap<Ip4Addr, MacAddr>>>,
    tap: &mut Tap,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
) -> Result<(), Box<dyn error::Error>> {
    let mymac = mac_address_by_name("tap0").unwrap().unwrap().bytes();
    let builder = PacketBuilder::ethernet2(mymac, *src_mac)
        .ipv4(MYIP, srcip, 64)
        .icmpv4(Icmpv4Type::EchoReply(header));
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, payload)?;
    tap.send(&result)?;

    Ok(())
}
