use std::collections::BTreeMap;
use std::error;
use std::net::Ipv4Addr;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

use dashmap::DashMap;

use etherparse::checksum::Sum16BitWords;
use etherparse::{
    ArpHardwareId, ArpOperation, ArpPacket, ArpPacketSlice, EtherType, Ethernet2Slice,
    IcmpEchoHeader, Icmpv4Slice, Icmpv4Type, IpNumber, Ipv4Slice, PacketBuilder, TcpHeader,
    TcpSlice,
};

use mac_address::mac_address_by_name;
use rand::Rng;
use tappers::{Interface, Tap};

//too much effort making them structs
type MacAddr = [u8; 6];
type Ip4Addr = [u8; 4];
type Port = u16;
const MYIP: [u8; 4] = [10, 0, 0, 4];

#[allow(unused)]
#[derive(Copy, Clone, Debug)]
enum ClosingTcp {
    Rx,
    Tx,
    RxAndTx,
}
#[derive(Debug)]
enum TcpStates {
    InProgress,
    Established,
    ClosingTcp(ClosingTcp),
}

#[allow(unused)]
struct SendState {
    nxt: u32,
    una: u32,
    win: u16,
}

#[allow(unused)]
struct RecvState {
    nxt: u32,
    win: u16,
}

struct TcpState {
    send: SendState,
    recv: RecvState,
    state: TcpStates,
    buffer: BTreeMap<u32, [u8; 1514]>,
}

//we have hardcoded window size currently
fn main() {
    let tap_name = Interface::new("tap0").unwrap();
    let mut tap = Tap::new_named(tap_name).unwrap();
    tap.add_addr(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    tap.set_up().unwrap();

    let mut recv_buf = [0; 1514];

    let mut tcp_state: Arc<RwLock<DashMap<(Ip4Addr, Port), TcpState>>> =
        Arc::new(RwLock::new(DashMap::new()));
    let mut arp_table: Arc<RwLock<DashMap<Ip4Addr, MacAddr>>> =
        Arc::new(RwLock::new(DashMap::new()));

    loop {
        tap.recv(&mut recv_buf).unwrap();
        handle_frame(&recv_buf, &mut arp_table, &mut tcp_state, &mut tap).ok();
    }
}

fn handle_frame(
    buf: &[u8],
    arp_table: &mut Arc<RwLock<DashMap<Ip4Addr, MacAddr>>>,
    tcp_state: &mut Arc<RwLock<DashMap<(Ip4Addr, Port), TcpState>>>,
    tap: &mut Tap,
) -> Result<(), Box<dyn error::Error>> {
    let frame = Ethernet2Slice::from_slice_without_fcs(buf)?;

    match frame.ether_type() {
        EtherType::ARP => handle_arp(frame.payload_slice(), arp_table, tap)?,
        EtherType::IPV4 => handle_ipv4(frame.payload_slice(), tcp_state, tap, &frame.source())?,
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
    tcp_state: &mut Arc<RwLock<DashMap<(Ip4Addr, Port), TcpState>>>,
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
                IpNumber::ICMP => {
                    handle_icmpv4(packet.payload().payload, tap, header.source(), src_mac)?
                }
                IpNumber::TCP => handle_tcp(
                    packet.payload().payload,
                    tcp_state,
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

fn handle_tcp(
    buf: &[u8],
    tcp_state: &mut Arc<RwLock<DashMap<(Ip4Addr, Port), TcpState>>>,
    tap: &mut Tap,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
) -> Result<(), Box<dyn error::Error>> {
    let packet = TcpSlice::from_slice(buf)?;
    // the rfc tells we need to validate this rst so we need to do that
    if packet.rst() {
        let table = tcp_state.write().unwrap();
        table.remove(&(srcip, packet.source_port()));
        return Ok(());
    }
    if packet.syn() {
        handle_tcp_syn(&packet, tcp_state, tap, srcip, src_mac)?;
        return Ok(());
    }

    let table = tcp_state.write().unwrap();
    let mut next_packet_buf: Option<[u8; 1514]> = None;
    if let Some(mut tcp) = table.get_mut(&(srcip, packet.source_port())) {
        if packet.sequence_number() == tcp.recv.nxt {
            if packet.ack() {
                tcp.send.una = packet.acknowledgment_number();

                match tcp.state {
                    TcpStates::InProgress => tcp.state = TcpStates::Established,
                    TcpStates::ClosingTcp(ClosingTcp::RxAndTx) => {
                        drop(tcp);
                        table.remove(&(srcip, packet.source_port()));
                        return Ok(());
                    }
                    _ => {}
                }
            }
            if !packet.payload().is_empty() {
                let payload: &[u8] = &[0x32, 0x34, 0x0a];
                tcp_send_ack(&packet, tcp.value_mut(), tap, src_mac, srcip, payload)?;
            }
            let next = &tcp.recv.nxt.clone();
            next_packet_buf = tcp.buffer.remove(next);

            //this does not handle overlaps currently
        } else if (packet.sequence_number() + packet.payload().len() as u32 - 1)
            <= tcp.recv.nxt + 64240
        {
            tcp.buffer
                .insert(packet.sequence_number(), buf.try_into().unwrap());
            let payload: &[u8] = &[];
            tcp_send_ack(&packet, tcp.value_mut(), tap, src_mac, srcip, payload)?;
        }
    } else {
        println!("something is wrong wuith the tcp state machine");
    }
    drop(table);
    if let Some(buff) = next_packet_buf {
        handle_tcp(&buff, tcp_state, tap, srcip, src_mac)?;
    }
    if packet.fin() {
        let table = tcp_state.write().unwrap();
        if let Some(mut tcp) = table.get_mut(&(srcip, packet.source_port())) {
            tcp.recv.nxt = packet.sequence_number() + 1;
            let payload: &[u8] = &[];
            tcp_send_ack(&packet, tcp.value_mut(), tap, src_mac, srcip, payload)?;

            match tcp.state {
                TcpStates::ClosingTcp(ClosingTcp::Tx) => {
                    tcp.state = TcpStates::ClosingTcp(ClosingTcp::RxAndTx);
                    tcp.deref_mut();
                    table.remove(tcp.key());
                }

                _ => tcp.state = TcpStates::ClosingTcp(ClosingTcp::Rx),
            }
            if let TcpStates::ClosingTcp(ClosingTcp::Rx) = tcp.state {
                let mut tcp_header = TcpHeader::new(
                    packet.destination_port(),
                    packet.source_port(),
                    tcp.send.nxt,
                    64240,
                );
                tcp_header.ack = true;
                tcp_header.fin = true;
                tcp_header.acknowledgment_number = tcp.recv.nxt;
                tcp.send.nxt += payload.len() as u32;
                tcp.state = TcpStates::ClosingTcp(ClosingTcp::RxAndTx);
                send_tcp(srcip, src_mac, tcp_header, payload, tap)?;
            }
        } else {
            println!("Something is wrong wuith the tcp state machine");
        }
    }
    Ok(())
}

// does not handle reordering of packets currently
fn tcp_send_ack(
    packet: &TcpSlice,
    tcp: &mut TcpState,
    tap: &mut Tap,
    src_mac: &[u8; 6],
    srcip: [u8; 4],
    payload: &[u8],
) -> Result<(), Box<dyn error::Error>> {
    tcp.recv.nxt += packet.payload().len() as u32;
    let mut tcp_header = TcpHeader::new(
        packet.destination_port(),
        packet.source_port(),
        tcp.send.nxt,
        64240,
    );
    tcp_header.ack = true;
    tcp_header.acknowledgment_number = tcp.recv.nxt;
    tcp.send.nxt += payload.len() as u32;

    send_tcp(srcip, src_mac, tcp_header, payload, tap)?;

    println!("Received {:?}", packet.payload());
    Ok(())
}
fn handle_tcp_syn(
    packet: &TcpSlice,
    tcp_state: &mut Arc<RwLock<DashMap<(Ip4Addr, Port), TcpState>>>,
    tap: &mut Tap,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
) -> Result<(), Box<dyn error::Error>> {
    let table = tcp_state.write().unwrap();
    let mut rng = rand::rng();
    let isn: u32 = rng.random();
    table
        .entry((srcip, packet.source_port()))
        .and_modify(|tcp_state| tcp_state.recv.nxt = packet.sequence_number())
        .or_insert(TcpState {
            send: SendState {
                nxt: isn + 1,
                una: isn,
                win: packet.window_size(),
            },
            recv: RecvState {
                nxt: packet.sequence_number() + 1,
                win: 64240,
            },
            state: TcpStates::InProgress,
            buffer: BTreeMap::new(),
        });
    let mut tcp_header =
        TcpHeader::new(packet.destination_port(), packet.source_port(), isn, 64240);
    if packet.ack() {
        if let Some(mut tcp) = table.get_mut(&(srcip, packet.source_port())) {
            tcp.send.una = packet.acknowledgment_number();
            if let TcpStates::InProgress = tcp.state {
                tcp.state = TcpStates::Established;
            }
        }
    } else {
        tcp_header.syn = true;
    }
    tcp_header.ack = true;
    tcp_header.acknowledgment_number = packet.sequence_number() + 1;

    let payload: &[u8] = &[];
    send_tcp(srcip, src_mac, tcp_header, payload, tap)?;
    Ok(())
}

fn send_tcp(
    srcip: [u8; 4],
    src_mac: &[u8; 6],
    tcp_header: TcpHeader,
    payload: &[u8],
    tap: &mut Tap,
) -> Result<(), Box<dyn error::Error>> {
    let mymac = mac_address_by_name("tap0").unwrap().unwrap().bytes();
    let builder = PacketBuilder::ethernet2(mymac, *src_mac)
        .ipv4(MYIP, srcip, 64)
        .tcp_header(tcp_header);
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, payload)?;
    tap.send(&result)?;

    Ok(())
}

fn handle_icmpv4(
    buf: &[u8],
    tap: &mut Tap,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
) -> Result<(), Box<dyn error::Error>> {
    let packet = Icmpv4Slice::from_slice(buf)?;

    match packet.icmp_type() {
        Icmpv4Type::EchoRequest(icmp_echo_header) => {
            handle_icmpv4_echo_request(icmp_echo_header, packet.payload(), tap, srcip, src_mac)?
        }
        _ => println!("Aint handling this yet"),
    }

    Ok(())
}

fn handle_icmpv4_echo_request(
    header: IcmpEchoHeader,
    payload: &[u8],
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
