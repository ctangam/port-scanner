use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportProtocol};
use rayon::prelude::*;
use std::env;
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    let args: Vec<String> = env::args().collect();
    dbg!(&args);

    if args.len() < 2 {
        println!("{} <host> [port]", args[0]);
        return;
    }

    let host = &args[1];

    if args.len() == 3 {
        let port = &args[2];
        println!("Scanning host: {host} port: {port}");

        scan(&host, port.parse().unwrap());
    } else {
        host.split(",")
            .flat_map(|h| {
                if h.ends_with("*") {
                    (1..256).map(|i| h.replace("*", &i.to_string())).collect()
                } else {
                    vec![h.to_string()]
                }
            })
            .for_each(|host| {
                println!("Scanning host: {host} on all ports");
                (1..=65535)
                    .into_par_iter()
                    .for_each(|port| scan(&host, port));
            });
    }
}

fn scan(host: &str, port: u16) {
    let protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, mut rx) = transport_channel(1024, protocol).unwrap();

    let source_ip = Ipv4Addr::new(127, 0, 0, 1);
    let dest_ip: Ipv4Addr = host.parse().unwrap();
    let source_port = 12345;
    let dest_port = port;

    let mut packet = [0u8; 20];
    let tcp_packet = build_packet(source_port, dest_port, source_ip, dest_ip, &mut packet);

    tx.send_to(tcp_packet, IpAddr::V4(dest_ip)).unwrap();

    let mut iter = pnet::transport::tcp_packet_iter(&mut rx);
    while let Ok((packet, addr)) = iter.next() {
        if addr == IpAddr::V4(dest_ip) && packet.get_destination() == source_port {
            if packet.get_flags() & TcpFlags::SYN != 0 && packet.get_flags() & TcpFlags::ACK != 0 {
                println!("Received SYN-ACK from {}", addr);
            } else if packet.get_flags() & TcpFlags::RST != 0 {
                println!("Received RST from {}", addr);
            }

            break;
        }
    }
}

fn build_packet<'a>(
    source_port: u16,
    dest_port: u16,
    source_ip: std::net::Ipv4Addr,
    dest_ip: std::net::Ipv4Addr,
    packet: &'a mut [u8],
) -> tcp::MutableTcpPacket<'a> {
    let mut tcp_packet = MutableTcpPacket::new(packet).unwrap();
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(1024);
    tcp_packet.set_sequence(1);
    tcp_packet.set_checksum(pnet::util::ipv4_checksum(
        tcp_packet.packet(),
        0,
        &[],
        &source_ip,
        &dest_ip,
        IpNextHeaderProtocols::Tcp,
    ));
    tcp_packet
}
