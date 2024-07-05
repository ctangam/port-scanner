use rayon::prelude::*;
use std::env;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

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

        match TcpStream::connect(format!("{host}:{port}")) {
            Ok(_) => println!("Port: {port} is open"),
            Err(_) => println!("Port: {port} is closed or filtered"),
        }
    } else {
        let mut hosts: Vec<String> = Vec::new();

        println!("Scanning host: {host} on all ports");

        (1..=65535)
            .into_par_iter()
            .filter_map(|port| format!("{host}:{port}").parse::<SocketAddr>().ok())
            .for_each(|addr| {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok() {
                    println!("Port: {} is open", addr.port());
                }
            });
    }
}
