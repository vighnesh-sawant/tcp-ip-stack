use std::cmp::max;
use std::collections::BTreeMap;
use std::error;
use std::net::Ipv4Addr;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use dashmap::DashMap;

use etherparse::checksum::Sum16BitWords;
use etherparse::{
    ArpHardwareId, ArpOperation, ArpPacket, ArpPacketSlice, EtherType, Ethernet2Slice,
    IcmpEchoHeader, Icmpv4Slice, Icmpv4Type, IpNumber, Ipv4Slice, PacketBuilder, TcpHeader,
    TcpOptionElement, TcpSlice,
};

use mac_address::mac_address_by_name;
use rand::Rng;
use tappers::{Interface, Tap};

use tokio::sync::watch;
use tokio::time::{self, Instant};

//too much effort making them structs
type MacAddr = [u8; 6];
type Ip4Addr = [u8; 4];
type Port = u16;

const MYIP: [u8; 4] = [10, 0, 0, 4];
const INFTIME: u64 = 365 * 24 * 3600;
static TIMER: OnceLock<Instant> = OnceLock::new();

#[allow(unused)] //this is for tx we dont use it yet but we need it
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

struct PacketBeforeTcpHeader {
    mymac: MacAddr,
    src_mac: MacAddr,
    srcip: Ip4Addr,
    payload: Box<[u8]>,
    tcp_header: TcpHeader,
}

struct SendState {
    nxt: u32,
    una: u32,
    win: u32,
    srtt: u32,
    rttvar: u32,
    rto: u32,
    ssthresh: u32,
    dupack: u16,
    tx: watch::Sender<Duration>,
    buffer: BTreeMap<u32, PacketBeforeTcpHeader>,
}

struct RecvState {
    nxt: u32,
    win: u16,
    buffer: BTreeMap<u32, Box<[u8]>>,
}

struct TcpState {
    send: SendState,
    recv: RecvState,
    state: TcpStates,
}

//we have hardcoded window size currently
#[tokio::main]
async fn main() {
    let tap_name = Interface::new("tap0").unwrap();
    let mut tap_raw = Tap::new_named(tap_name).unwrap();
    tap_raw.add_addr(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    tap_raw.set_up().unwrap();
    let tap = Arc::new(Mutex::new(tap_raw));
    let mymac = mac_address_by_name("tap0").unwrap().unwrap().bytes();

    TIMER.get_or_init(Instant::now);

    let mut recv_buf = [0; 1514];

    let tcp_state: Arc<DashMap<(Ip4Addr, Port), TcpState>> = Arc::new(DashMap::new());

    let arp_table: Arc<DashMap<Ip4Addr, MacAddr>> = Arc::new(DashMap::new());

    loop {
        {
            let tap = tap.lock().unwrap();
            tap.recv(&mut recv_buf).unwrap();
        }
        let mut arp_table_arc = arp_table.clone();
        let mut tcp_state_arc = tcp_state.clone();
        let mut tap_arc = tap.clone();

        handle_frame(
            &recv_buf,
            &mut arp_table_arc,
            &mut tcp_state_arc,
            &mut tap_arc,
            &mymac,
        )
        .ok();
    }
}

fn handle_frame(
    buf: &[u8],
    arp_table: &mut Arc<DashMap<Ip4Addr, MacAddr>>,
    tcp_state: &mut Arc<DashMap<(Ip4Addr, Port), TcpState>>,
    tap: &mut Arc<Mutex<tappers::Tap>>,
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let frame = Ethernet2Slice::from_slice_without_fcs(buf)?;

    match frame.ether_type() {
        EtherType::ARP => handle_arp(frame.payload_slice(), arp_table, tap, mymac)?,
        EtherType::IPV4 => handle_ipv4(
            frame.payload_slice(),
            tcp_state,
            tap,
            &frame.source(),
            mymac,
        )?,
        _ => println!("Aint handling this yet {:?}", frame.ether_type()),
    }

    Ok(())
}
#[allow(clippy::collapsible_if)] //prefer writing my ifs like this 
fn handle_arp(
    buf: &[u8],
    arp_table: &mut Arc<DashMap<Ip4Addr, MacAddr>>,
    tap: &mut Arc<Mutex<tappers::Tap>>,
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let packet = ArpPacketSlice::from_slice(buf)?;

    if packet.hw_addr_type() == ArpHardwareId::ETHERNET {
        if packet.proto_addr_type() == EtherType::IPV4 {
            arp_table.insert(
                packet.sender_protocol_addr().try_into()?,
                packet.sender_hw_addr().try_into()?,
            );

            if packet.target_protocol_addr() == MYIP {
                if packet.operation() == ArpOperation::REQUEST {
                    let reply = ArpPacket::new(
                        ArpHardwareId::ETHERNET,
                        EtherType::IPV4,
                        ArpOperation::REPLY,
                        mymac,
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

                    {
                        let tap = tap.lock().unwrap();
                        tap.send(&result)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_ipv4(
    buf: &[u8],
    tcp_state: &mut Arc<DashMap<(Ip4Addr, Port), TcpState>>,
    tap: &mut Arc<Mutex<tappers::Tap>>,
    src_mac: &[u8; 6],
    mymac: &MacAddr,
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
                    tap,
                    header.source(),
                    src_mac,
                    mymac,
                )?,
                IpNumber::TCP => handle_tcp(
                    packet.payload().payload,
                    tcp_state,
                    tap,
                    header.source(),
                    src_mac,
                    mymac,
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
    tcp_state: &mut Arc<DashMap<(Ip4Addr, Port), TcpState>>,
    tap: &mut Arc<Mutex<tappers::Tap>>,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let packet = TcpSlice::from_slice(buf)?;

    // the rfc tells we need to validate this rst so we need to do that
    if packet.rst() {
        tcp_state.remove(&(srcip, packet.source_port()));
        return Ok(());
    }

    if packet.syn() {
        handle_tcp_syn(&packet, tcp_state, tap, srcip, src_mac, mymac)?;
        return Ok(());
    }

    let mut next_packet_buf: Option<Box<[u8]>> = None;

    if let Some(mut tcp) = tcp_state.get_mut(&(srcip, packet.source_port())) {
        if packet.sequence_number() == tcp.recv.nxt {
            if packet.ack() {
                if tcp.send.una == packet.acknowledgment_number() {
                    tcp.send.dupack += 1;
                    if tcp.send.dupack >= 3 {
                        tcp.send.ssthresh =
                            max(((tcp.send.buffer.values().count() * 1500) / 2) as u32, 3000);
                        tcp.send.win = tcp.send.ssthresh + 4500;
                    }

                    tcp.send.tx.send(Duration::from_nanos(1))?;
                } else {
                    #[allow(clippy::collapsible_else_if)] // why does clippy want to make my code
                    // bad?????
                    if tcp.send.win <= tcp.send.ssthresh {
                        if let Some(v) = packet.acknowledgment_number().checked_sub(tcp.send.una) {
                            tcp.send.win += v;
                        }
                    } else {
                        if let Some(value) = tcp.send.win.checked_add(1500 * 1500 / tcp.send.win) {
                            tcp.send.win = value;
                        } else {
                            tcp.send.win = u32::MAX;
                        }
                    }
                    if tcp.send.dupack >= 3 {
                        tcp.send.dupack = 0;
                        tcp.send.win = tcp.send.ssthresh;
                    }
                }
                tcp.send.una = packet.acknowledgment_number();

                tcp.send.buffer = tcp.send.buffer.split_off(&packet.acknowledgment_number());
                tcp.send.buffer.remove(&packet.acknowledgment_number());

                tcp.send
                    .tx
                    .send(Duration::from_millis(tcp.send.rto as u64))?;

                match tcp.state {
                    TcpStates::InProgress => tcp.state = TcpStates::Established,
                    TcpStates::ClosingTcp(ClosingTcp::RxAndTx) => {
                        drop(tcp);
                        tcp_state.remove(&(srcip, packet.source_port()));
                        return Ok(());
                    }
                    _ => {}
                }
            }

            if !packet.payload().is_empty() {
                let payload: &[u8] = &[0x32, 0x34, 0x0a];
                tcp_send_ack(
                    &packet,
                    tcp.value_mut(),
                    tap,
                    src_mac,
                    srcip,
                    payload,
                    mymac,
                )?;
            }

            let next = &tcp.recv.nxt.clone();
            next_packet_buf = tcp.recv.buffer.remove(next);
            if next_packet_buf.is_none() {
                tcp.send.tx.send(Duration::from_secs(INFTIME))?;
            }

            //this does not handle overlaps currently
        } else if (packet.sequence_number() + packet.payload().len() as u32 - 1) as i32
            <= (tcp.recv.nxt + tcp.recv.win as u32) as i32
        {
            tcp.recv
                .buffer
                .insert(packet.sequence_number(), Box::from(buf));
            let payload: &[u8] = &[];
            tcp_send_ack(
                &packet,
                tcp.value_mut(),
                tap,
                src_mac,
                srcip,
                payload,
                mymac,
            )?;
        }
    } else {
        println!("something is wrong wuith the tcp state machine");
    }
    if let Some(buff) = next_packet_buf {
        handle_tcp(&buff, tcp_state, tap, srcip, src_mac, mymac)?;
    }

    if packet.fin() {
        if let Some(mut tcp) = tcp_state.get_mut(&(srcip, packet.source_port())) {
            tcp.recv.nxt = packet.sequence_number() + 1;
            let payload: &[u8] = &[];
            tcp_send_ack(
                &packet,
                tcp.value_mut(),
                tap,
                src_mac,
                srcip,
                payload,
                mymac,
            )?;

            match tcp.state {
                TcpStates::ClosingTcp(ClosingTcp::Tx) => {
                    tcp.state = TcpStates::ClosingTcp(ClosingTcp::RxAndTx);
                    tcp.deref_mut();
                    tcp_state.remove(tcp.key());
                }

                _ => tcp.state = TcpStates::ClosingTcp(ClosingTcp::Rx),
            }

            if let TcpStates::ClosingTcp(ClosingTcp::Rx) = tcp.state {
                let mut tcp_header = TcpHeader::new(
                    packet.destination_port(),
                    packet.source_port(),
                    tcp.send.nxt,
                    tcp.recv.win,
                );
                tcp_header.ack = true;

                handle_timestamp_option(&packet, &mut tcp_header, tcp.value_mut())?;

                tcp_header.fin = true;
                tcp_header.acknowledgment_number = tcp.recv.nxt;
                tcp.send.nxt += payload.len() as u32;
                tcp.state = TcpStates::ClosingTcp(ClosingTcp::RxAndTx);

                send_tcp(
                    srcip,
                    src_mac,
                    tcp.value_mut(),
                    tcp_header,
                    payload,
                    tap,
                    mymac,
                )?;
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
    tap: &mut Arc<Mutex<tappers::Tap>>,
    src_mac: &[u8; 6],
    srcip: [u8; 4],
    payload: &[u8],
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    tcp.recv.nxt += packet.payload().len() as u32;
    let mut tcp_header = TcpHeader::new(
        packet.destination_port(),
        packet.source_port(),
        tcp.send.nxt,
        tcp.recv.win,
    );
    tcp_header.ack = true;
    tcp_header.acknowledgment_number = tcp.recv.nxt;
    tcp.send.nxt += payload.len() as u32;

    handle_timestamp_option(packet, &mut tcp_header, tcp)?;

    send_tcp(srcip, src_mac, tcp, tcp_header, payload, tap, mymac)?;

    // println!("Received {:?}", packet.payload());
    Ok(())
}

fn handle_tcp_syn(
    packet: &TcpSlice,
    tcp_state: &mut Arc<DashMap<(Ip4Addr, Port), TcpState>>,
    tap: &mut Arc<Mutex<tappers::Tap>>,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let mut rng = rand::rng();
    let isn: u32 = rng.random();

    let (tx, mut rx): (watch::Sender<Duration>, watch::Receiver<Duration>) =
        watch::channel(Duration::from_secs(INFTIME));

    if !tcp_state.contains_key(&(srcip, packet.source_port())) {
        let mut tcp_state_arc = tcp_state.clone();
        let mut tap_arc = tap.clone();
        let key = (srcip, packet.source_port());

        tokio::spawn(async move {
            let timer = time::sleep_until(Instant::now() + Duration::from_secs(INFTIME));
            let mut rto = Duration::from_secs(INFTIME);
            tokio::pin!(timer);
            loop {
                tokio::select! {
                msg = rx.changed() => {
                    if let Ok(()) = msg {
                        timer.as_mut().reset(Instant::now() + *rx.borrow_and_update());
                        rto = *rx.borrow_and_update();
                        // println!("Rto {:}",rto.as_millis());
                    }
                }

                _ = &mut timer => {
                    let mut adjust_ssthresh = false;
                    if rto == *rx.borrow_and_update() {
                       adjust_ssthresh = true;
                    }
                    rto *= 2;
                    timer.as_mut().reset(Instant::now() +rto);
                    handle_timer_rtx(&mut tcp_state_arc,&mut tap_arc,&key,&adjust_ssthresh).unwrap();

                    }
                }
            }
        });
    }

    tcp_state
        .entry((srcip, packet.source_port()))
        .and_modify(|tcp_state| tcp_state.recv.nxt = packet.sequence_number() + 1)
        .or_insert(TcpState {
            send: SendState {
                nxt: isn + 1,
                una: isn,
                win: 4400,
                srtt: 0,
                rttvar: 0,
                rto: 1000,
                ssthresh: packet.window_size() as u32,
                dupack: 0,
                tx,
                buffer: BTreeMap::new(),
            },
            recv: RecvState {
                nxt: packet.sequence_number() + 1,
                win: 64240,
                buffer: BTreeMap::new(),
            },
            state: TcpStates::InProgress,
        });

    let mut tcp_header =
        TcpHeader::new(packet.destination_port(), packet.source_port(), isn, 64240);

    if packet.ack() {
        if let Some(mut tcp) = tcp_state.get_mut(&(srcip, packet.source_port())) {
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
    if let Some(mut tcp) = tcp_state.get_mut(&(srcip, packet.source_port())) {
        handle_timestamp_option(packet, &mut tcp_header, tcp.value_mut())?;
        send_tcp(
            srcip,
            src_mac,
            tcp.value_mut(),
            tcp_header,
            payload,
            tap,
            mymac,
        )?;
    }
    Ok(())
}

fn handle_timer_rtx(
    tcp_state: &mut Arc<DashMap<(Ip4Addr, Port), TcpState>>,
    tap: &mut Arc<Mutex<tappers::Tap>>,
    key: &(Ip4Addr, Port),
    adjust_ssthresh: &bool,
) -> Result<(), Box<dyn error::Error>> {
    if let Some(mut tcp) = tcp_state.get_mut(key) {
        if let Some(pair) = tcp.send.buffer.first_key_value() {
            {
                let mut tcp_header = pair.1.tcp_header.clone();
                for options in pair.1.tcp_header.options.elements_iter() {
                    if let TcpOptionElement::Timestamp(_tsval, tsecr) = options.unwrap() {
                        let curr_time =
                            TIMER.get_or_init(Instant::now).elapsed().as_millis() as u32;

                        let elements = [
                            TcpOptionElement::Noop,
                            TcpOptionElement::Noop,
                            TcpOptionElement::Timestamp(curr_time, tsecr),
                        ];

                        tcp_header.set_options(&elements)?;
                    }
                }
                let builder = PacketBuilder::ethernet2(pair.1.mymac, pair.1.src_mac)
                    .ipv4(MYIP, pair.1.srcip, 64)
                    .tcp_header(tcp_header);
                let payload = &*pair.1.payload;
                let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
                builder.write(&mut result, payload)?;

                if *adjust_ssthresh {
                    tcp.send.win = 1500;
                    tcp.send.ssthresh =
                        max(((tcp.send.buffer.values().count() * 1500) / 2) as u32, 3000);
                }

                {
                    let tap = tap.lock().unwrap();
                    tap.send(&result)?;
                }
            }
        } else {
            tcp.send.tx.send(Duration::from_secs(INFTIME))?;
        }
    }

    Ok(())
}
fn handle_timestamp_option(
    packet: &TcpSlice,
    tcp_header: &mut TcpHeader,
    tcp: &mut TcpState,
) -> Result<(), Box<dyn error::Error>> {
    for options in packet.options_iterator() {
        if let TcpOptionElement::Timestamp(tsval, tsecr) = options.unwrap() {
            let curr_time = TIMER.get_or_init(Instant::now).elapsed().as_millis() as u32;

            let elements = [
                TcpOptionElement::Noop,
                TcpOptionElement::Noop,
                TcpOptionElement::Timestamp(curr_time, tsval),
            ];
            tcp_header.set_options(&elements)?;

            if tsecr != 0 {
                let r = curr_time - tsecr;

                // println!("RTT {:?}", r);
                if r > 0 {
                    if tcp.send.srtt == 0 {
                        tcp.send.srtt = r;
                        tcp.send.rttvar = r / 2;
                        tcp.send.rto = tcp.send.srtt + max(1000, 4 * tcp.send.rttvar);
                    } else {
                        let alpha = 125;
                        let beta = 250;
                        tcp.send.rttvar = ((1000 - beta) * tcp.send.rttvar
                            + beta * (tcp.send.srtt.abs_diff(r)))
                            / 1000;
                        tcp.send.srtt = ((1000 - alpha) * tcp.send.srtt + alpha * r) / 1000;
                        tcp.send.rto = tcp.send.srtt + max(1000, 4 * tcp.send.rttvar);
                    }
                }
            }
        }
    }
    Ok(())
}

fn send_tcp(
    srcip: [u8; 4],
    src_mac: &[u8; 6],
    tcp: &mut TcpState,
    tcp_header: TcpHeader,
    payload: &[u8],
    tap: &mut Arc<Mutex<tappers::Tap>>,
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let seq_num = tcp_header.sequence_number;

    if *tcp.send.tx.subscribe().borrow_and_update() == Duration::from_secs(INFTIME) {
        tcp.send
            .tx
            .send(Duration::from_millis(tcp.send.rto as u64))?;
    }

    let builder = PacketBuilder::ethernet2(*mymac, *src_mac)
        .ipv4(MYIP, srcip, 64)
        .tcp_header(tcp_header.clone());
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, payload)?;

    tcp.send.buffer.insert(
        seq_num + payload.len() as u32,
        PacketBeforeTcpHeader {
            mymac: *mymac,
            src_mac: *src_mac,
            srcip,
            payload: Box::from(payload),
            tcp_header,
        },
    );

    //i think this not exactly according to rfc but think this will give better performance?
    if tcp.send.una + tcp.send.win >= seq_num {
        {
            let tap = tap.lock().unwrap();
            tap.send(&result)?;
        }
    }

    Ok(())
}

fn handle_icmpv4(
    buf: &[u8],
    tap: &mut Arc<Mutex<tappers::Tap>>,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let packet = Icmpv4Slice::from_slice(buf)?;

    match packet.icmp_type() {
        Icmpv4Type::EchoRequest(icmp_echo_header) => handle_icmpv4_echo_request(
            icmp_echo_header,
            packet.payload(),
            tap,
            srcip,
            src_mac,
            mymac,
        )?,
        _ => println!("Aint handling this yet"),
    }

    Ok(())
}

fn handle_icmpv4_echo_request(
    header: IcmpEchoHeader,
    payload: &[u8],
    tap: &mut Arc<Mutex<tappers::Tap>>,
    srcip: [u8; 4],
    src_mac: &[u8; 6],
    mymac: &MacAddr,
) -> Result<(), Box<dyn error::Error>> {
    let builder = PacketBuilder::ethernet2(*mymac, *src_mac)
        .ipv4(MYIP, srcip, 64)
        .icmpv4(Icmpv4Type::EchoReply(header));
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, payload)?;

    {
        let tap = tap.lock().unwrap();
        tap.send(&result)?;
    }

    Ok(())
}
