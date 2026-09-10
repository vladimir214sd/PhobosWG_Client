// STUN protocol masking matching Phobos / wg-obfuscator

use rand::Rng;

pub const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

pub const STUN_BINDING_REQ: u16 = 0x0001;
pub const STUN_BINDING_RESP: u16 = 0x0101;
pub const STUN_DATA_INDICATION: u16 = 0x0115;

pub const STUN_ATTR_DATA: u16 = 0x0013;
#[allow(dead_code)]
pub const STUN_ATTR_XORMAPPED: u16 = 0x0020;
pub const STUN_ATTR_FINGERPRINT: u16 = 0x8028;
pub const STUN_FINGERPRINT_XOR: u32 = 0x5354554E;

#[allow(dead_code)]
pub const STUN_HEADER_SIZE: usize = 20;
pub const STUN_DATA_IND_HEADER_SIZE: usize = 24;

/// Checks if packet has STUN magic cookie at offset 4..8
pub fn is_stun_packet(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[4..8] == STUN_COOKIE
}

/// Extracts the STUN message type
pub fn stun_message_type(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        None
    } else {
        Some(u16::from_be_bytes([buf[0], buf[1]]))
    }
}

/// Wraps payload in STUN Data Indication header (24 bytes header prepended)
pub fn stun_wrap_data_indication(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > (u16::MAX as usize) {
        return None;
    }
    let mut out = Vec::with_capacity(STUN_DATA_IND_HEADER_SIZE + payload.len());

    let mut txid = [0u8; 12];
    rand::thread_rng().fill(&mut txid);

    // Header (20 bytes)
    // Type: 0x0115 (Data Indication)
    out.extend_from_slice(&STUN_DATA_INDICATION.to_be_bytes());
    // Length: in Phobos framing this is set to 0 in header
    out.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    out.extend_from_slice(&STUN_COOKIE);
    // Transaction ID
    out.extend_from_slice(&txid);

    // Attribute: STUN_ATTR_DATA (0x0013), length = payload.len()
    out.extend_from_slice(&STUN_ATTR_DATA.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());

    // Payload
    out.extend_from_slice(payload);
    Some(out)
}

/// Unwraps a STUN Data Indication packet, returning the inner payload.
pub fn stun_unwrap_data_indication(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < STUN_DATA_IND_HEADER_SIZE {
        return None;
    }
    if !is_stun_packet(buf) {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != STUN_DATA_INDICATION {
        return None;
    }

    let attr_type = u16::from_be_bytes([buf[20], buf[21]]);
    if attr_type != STUN_ATTR_DATA {
        return None;
    }

    let data_len = u16::from_be_bytes([buf[22], buf[23]]) as usize;
    if STUN_DATA_IND_HEADER_SIZE + data_len > buf.len() {
        return None;
    }

    Some(&buf[STUN_DATA_IND_HEADER_SIZE..STUN_DATA_IND_HEADER_SIZE + data_len])
}

/// Builds a STUN Binding Request (28 bytes) with CRC32 Fingerprint.
pub fn stun_build_binding_request() -> [u8; 28] {
    let mut pkt = [0u8; 28];
    let mut txid = [0u8; 12];
    rand::thread_rng().fill(&mut txid);

    // Type: 0x0001 (Binding Request)
    pkt[0..2].copy_from_slice(&STUN_BINDING_REQ.to_be_bytes());
    // Length: 8 bytes (fingerprint attr)
    pkt[2..4].copy_from_slice(&8u16.to_be_bytes());
    // Magic Cookie
    pkt[4..8].copy_from_slice(&STUN_COOKIE);
    // TxID
    pkt[8..20].copy_from_slice(&txid);

    // Fingerprint Attribute
    pkt[20..22].copy_from_slice(&STUN_ATTR_FINGERPRINT.to_be_bytes());
    pkt[22..24].copy_from_slice(&4u16.to_be_bytes());

    // CRC32 of first 20 bytes XORed with 0x5354554E
    let crc = crc32fast::hash(&pkt[..20]) ^ STUN_FINGERPRINT_XOR;
    pkt[24..28].copy_from_slice(&crc.to_be_bytes());

    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_wrap_unwrap() {
        let payload = b"wireguard-obfuscated-packet-bytes";
        let wrapped = stun_wrap_data_indication(payload).expect("must wrap");
        assert_eq!(wrapped.len(), 24 + payload.len());
        assert!(is_stun_packet(&wrapped));

        let unwrapped = stun_unwrap_data_indication(&wrapped).expect("must unwrap");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn test_stun_binding_request_format() {
        let req = stun_build_binding_request();
        assert_eq!(req.len(), 28);
        assert!(is_stun_packet(&req));
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQ);
        assert_eq!(u16::from_be_bytes([req[20], req[21]]), STUN_ATTR_FINGERPRINT);
    }

    #[test]
    fn test_stun_wrap_bounds_check() {
        let oversized = vec![0u8; 70000];
        let wrapped = stun_wrap_data_indication(&oversized);
        assert!(wrapped.is_none(), "Oversized payload exceeding u16::MAX must return None");
    }
}
