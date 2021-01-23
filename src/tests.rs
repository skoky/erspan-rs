use std::str::FromStr;
use crate::{erspan_decap, ErspanError, ErspanVersion};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::util::MacAddr;
use std::net::IpAddr;

#[test]
fn erspan_decap_packet() {
    let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100088be7e088837100100010000000054b20307eeed6cab051f0c74080045000029250e000039116cb059bb82400a000a0b2703e1f60015fab0ee1c108eee4ece4a36cd840096";
    let packet_bytes = &hex::decode(packet).unwrap();
    let original_packet = match erspan_decap(packet_bytes, false) {
        Ok(result) => {
            assert_eq!(result.version, ErspanVersion::Version2);
            assert_eq!(result.vlan, 1);
            assert_eq!(result.gre_header.version, 0);
            assert_eq!(result.gre_header.checksum_flag, false);
            assert_eq!(result.gre_header.key_flag, false);
            assert_eq!(result.gre_header.sequence_num_flag, true);
            assert_eq!(result.original_data_packet.len() > 0, true);
            assert_eq!(result.gre_header.sequence_number.unwrap(), 2114488375);
            assert_eq!(result.gre_header.checksum, None);
            assert_eq!(result.gre_header.key, None);
            assert_eq!(result.source, IpAddr::from_str("10.0.10.1").unwrap());
            assert_eq!(result.destination, IpAddr::from_str("10.0.10.133").unwrap());
            result.original_data_packet
        }
        Err(e) => panic!(e)
    };

    assert_eq!(original_packet.len(), 55);
    let eframe = &EthernetPacket::new(original_packet.as_slice()).unwrap();
    assert_eq!(eframe.get_ethertype(), EtherTypes::Ipv4);
    assert_eq!(eframe.get_source(), MacAddr::from_str("6c:ab:05:1f:0c:74").unwrap());
    assert_eq!(eframe.get_destination(), MacAddr::from_str("54:b2:03:07:ee:ed").unwrap());
}

#[test]
fn erspan_decap_packet_failure1() {
    let packet = "52";
    let packet_bytes = &hex::decode(packet).unwrap();
    match erspan_decap(packet_bytes, false) {
        Ok(_result) => panic!("Unexpected end"),
        Err(e) => assert_eq!(e, ErspanError::UnknownPacket)
    }
}

#[test]
fn erspan_decap_packet_no_erspan() {
    let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100089be7e088837100100010000000054b20307eeed6cab051f0c74080045000029250e000039116cb059bb82400a000a0b2703e1f60015fab0ee1c108eee4ece4a36cd840096";
    let packet_bytes = &hex::decode(packet).unwrap();
    match erspan_decap(packet_bytes, false) {
        Ok(_result) => panic!("Unexpected end"),
        Err(e) => assert_eq!(e, ErspanError::InvalidGrePacketType)
    }
}

#[test]
fn erspan_decap_packet_too_short() {
    let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100088be7e08883710010001";
    let packet_bytes = &hex::decode(packet).unwrap();
    match erspan_decap(packet_bytes, false) {
        Ok(_result) => panic!("Unexpected end"),
        Err(e) => assert_eq!(e, ErspanError::PacketTooShort)
    }
}

#[test]
fn erspan_decap_packet_invalid_ipv4() {
    let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a";
    let packet_bytes = &hex::decode(packet).unwrap();
    match erspan_decap(packet_bytes, false) {
        Ok(_result) => panic!("Unexpected end"),
        Err(e) => assert_eq!(e, ErspanError::InvalidIpV4Packet)
    }
}

#[test]
fn erspan_decap_packet_invalid_ipv4_x() {
    let packet = "9801a7a0c751525400349b810800451000b0398f40004006d8030a000a8c0a000a1a0016e4fe28aa45f22318fe3b801801f5294800000101080adf7040c64ef704c0380dc7040b31e56e14329632a5da156d35a71647065331762f829479e270f9dc39998316313d0262d30cb459d165a7f28043d23edbaee8a0837744963dc1dc8920ac028a021e1d51ae99d5a873fb287215f7f2a18065e9919417da786cf05b65d2a4f43c9113ddde9df355c3630b3ff31a90f1588531c8a7d3ef636b";
    let packet_bytes = &hex::decode(packet).unwrap();
    match erspan_decap(packet_bytes, false) {
        Ok(_result) =>
            panic!("Unexpected end"),
        Err(e) => assert_eq!(e, ErspanError::InvalidTransportProtocol)
    }
}


