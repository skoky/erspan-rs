mod tests;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::io::{Cursor};
use std::net::IpAddr;
use byteorder::{BigEndian, ReadBytesExt};
use thiserror::Error;

pub struct GreHeader {
    flags_and_version: u16,
    sequence_number: u32,
}

pub struct ErspanHeader {
    gre_header: GreHeader,
    version: ErspanVersion,
    vlan: u16,
    original_data_packet: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum ErspanVersion {
    Version1 = 0,
    Version2 = 1,
    Unknown,
}

#[derive(Error, Debug, PartialEq)]
pub enum ErspanError {
    /// Represents an empty source. For example, an empty text file being given
    /// as input to `count_words()`.
    #[error("Unknown Ethernet packet type")]
    UnknownPacket,

    #[error("Unknown IpV4 packet type")]
    InvalidIpV4Packet,

    #[error("Unknown transport protocol, not GRE/ERSPAN")]
    InvalidTransportProtocol,

    #[error("Packet too short")]
    PacketTooShort,

    #[error("GRE protocol not containing ERSPAN")]
    InvalidGrePacketType,
}

fn erspan_decap(erspan_packet: &[u8], _is_interface_loopback: bool) -> Result<ErspanHeader, ErspanError> {
    match EthernetPacket::new(erspan_packet) {
        Some(eframe) => {
            match eframe.get_ethertype() {
                EtherTypes::Ipv4 => handle_ipv4_packet(&eframe),
                _ => Err(ErspanError::UnknownPacket)
            }
        }
        _ => Err(ErspanError::UnknownPacket)
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) -> Result<ErspanHeader, ErspanError> {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        )
    } else {
        Err(ErspanError::InvalidIpV4Packet)
    }
}

fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) -> Result<ErspanHeader, ErspanError> {
    match protocol {
        IpNextHeaderProtocols::Gre => {
            handle_gre_packet(source, destination, packet)
        }
        _ =>
            Err(ErspanError::InvalidTransportProtocol)
    }
}


pub fn handle_gre_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Result<ErspanHeader, ErspanError> {
    let gre_headers_size = 8 + 8;  // gre + erspan headers

    if packet.len() < gre_headers_size {
        return
            Err(ErspanError::PacketTooShort);
    }

    // GRE header
    let mut rdr = Cursor::new(&packet);
    let num = rdr.read_u16::<BigEndian>().unwrap();
    let proto_type = rdr.read_u16::<BigEndian>().unwrap();

    if proto_type != 0x88be {   // ERSPAN packet type constant
        return Err(ErspanError::InvalidGrePacketType);
    }

    let seq = rdr.read_u32::<BigEndian>().unwrap();

    let version_and_vlan = rdr.read_u16::<BigEndian>().unwrap();
    let version_num = version_and_vlan >> 12;
    let version = match version_num {
        0 => ErspanVersion::Version1,
        1 => ErspanVersion::Version2,
        _ => ErspanVersion::Unknown
    };
    let vlan = version_and_vlan & 0x0FFF;

    let (_, data) = packet.split_at(gre_headers_size);
    let buf = Vec::from(data);

    // TODO other flags

    return Ok(ErspanHeader {
        gre_header: GreHeader {
            flags_and_version: num,
            sequence_number: seq,
        },
        version,
        vlan,
        original_data_packet: buf,
    });
}
