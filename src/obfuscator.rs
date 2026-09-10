// Obfuscator implementation matching Phobos / wg-obfuscator

use rand::Rng;
use crate::crc8::xor_data;

pub const TYPE_HANDSHAKE: u32 = 1;
pub const TYPE_HANDSHAKE_RESP: u32 = 2;
pub const TYPE_COOKIE: u32 = 3;
pub const TYPE_DATA: u32 = 4;

pub const MAX_DUMMY_LENGTH_TOTAL: usize = 1024;
pub const MAX_DUMMY_LENGTH_HANDSHAKE: usize = 512;
pub const DEFAULT_MAX_DUMMY: usize = 4;

#[derive(Clone, Debug)]
pub struct Obfuscator {
    key: Vec<u8>,
    max_dummy: usize,
    obfuscate_bytes: usize,
}

impl Obfuscator {
    pub fn new(key: Vec<u8>, max_dummy: usize, obfuscate_bytes: usize) -> Self {
        Self {
            key,
            max_dummy,
            obfuscate_bytes,
        }
    }

    #[allow(dead_code)]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn packet_type(buf: &[u8]) -> Option<u32> {
        if buf.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    pub fn is_known_packet_type(t: u32) -> bool {
        (TYPE_HANDSHAKE..=TYPE_DATA).contains(&t)
    }

    pub fn is_obfuscated(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        data[0] < 1 || data[0] > 4 || (data[1] | data[2] | data[3]) != 0
    }

    /// Encodes a plain WireGuard packet buffer in-place and appends dummy bytes if needed.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        if buf.len() < 4 {
            return;
        }

        let orig_len = buf.len();
        let partial = self.obfuscate_bytes > 0 && self.obfuscate_bytes < orig_len;

        let packet_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

        let mut rng = rand::thread_rng();
        // rnd is non-zero (1..=255)
        let rnd: u8 = rng.gen_range(1..=255);
        buf[0] ^= rnd;
        buf[1] = rnd;

        let mut dummy_length: usize = 0;
        if !partial && orig_len < MAX_DUMMY_LENGTH_TOTAL {
            let mut max_dummy = MAX_DUMMY_LENGTH_TOTAL - orig_len;
            if self.obfuscate_bytes > 0 {
                let partial_room = self.obfuscate_bytes.saturating_sub(orig_len) + 1;
                if partial_room < max_dummy {
                    max_dummy = partial_room;
                }
            }

            match packet_type {
                TYPE_HANDSHAKE | TYPE_HANDSHAKE_RESP => {
                    let limit = max_dummy.min(MAX_DUMMY_LENGTH_HANDSHAKE);
                    if limit > 0 {
                        dummy_length = rng.gen_range(0..limit);
                    }
                }
                TYPE_COOKIE | TYPE_DATA => {
                    if self.max_dummy > 0 {
                        let limit = max_dummy.min(self.max_dummy);
                        if limit > 0 {
                            dummy_length = rng.gen_range(0..limit);
                        }
                    }
                }
                _ => {}
            }
        }

        buf[2] = (dummy_length & 0xFF) as u8;
        buf[3] = ((dummy_length >> 8) & 0xFF) as u8;

        if dummy_length > 0 {
            let start = buf.len();
            buf.resize(start + dummy_length, 0);
            rng.fill(&mut buf[start..]);
        }

        let xor_len = if partial {
            self.obfuscate_bytes
        } else {
            buf.len()
        };
        xor_data(&mut buf[..xor_len], &self.key);
    }

    /// Decodes an obfuscated packet buffer in-place.
    /// Returns true if decoding succeeded and resulted in a valid WireGuard packet type.
    pub fn decode(&self, buf: &mut Vec<u8>) -> bool {
        if buf.len() < 4 {
            return false;
        }

        let partial = self.obfuscate_bytes > 0 && self.obfuscate_bytes < buf.len();
        let xor_len = if partial {
            self.obfuscate_bytes
        } else {
            buf.len()
        };
        xor_data(&mut buf[..xor_len], &self.key);

        if !Self::is_obfuscated(buf) {
            // Version 0 or un-obfuscated
            return true;
        }

        buf[0] ^= buf[1];
        let dummy_len = (buf[2] as usize) | ((buf[3] as usize) << 8);
        if dummy_len > buf.len() - 4 {
            return false;
        }
        let real_len = buf.len() - dummy_len;
        buf.truncate(real_len);
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;

        // Verify valid packet type
        let t = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Self::is_known_packet_type(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(b: &[u8]) -> String {
        b.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    #[test]
    fn test_golden_decode_phobos_vector() {
        let key = b"phobos";
        let encoded_hex = "65d571e8d76516a55260138f8a0e8d899627ba50abf4f48d3c5299831b779b62b3b6f6";
        let expected_decoded_hex = "030000002f61faa0be86f457921ec37c0e460cf0d703d07dc5f5661a45013340";

        let obf = Obfuscator::new(key.to_vec(), 4, 0);
        let mut buf = hex_to_bytes(encoded_hex);
        let ok = obf.decode(&mut buf);
        assert!(ok, "decode must succeed");
        assert_eq!(bytes_to_hex(&buf), expected_decoded_hex);
    }

    #[test]
    fn test_golden_decode_k_vector() {
        let key = b"k";
        let encoded_hex = "3a6be0fdd2575784738736cc0fd42e3ca248482f4c3f1eb9e583e9d67b2d5d2cac723abe5347bb6cb88eed6a65243c63f996b2f00a007e99f3e8559a11bdb1125fe4f6d7aaaf906f5adb09e22b7d7ba60cddd448fa74e714824e27de361d1efca94dc58bd29550a5ee8830c0b42da0d177054166c6698771d8ebb7cff535ff4b1821039ccc17601bc356784459395c06a33322e1c9289f2e4284938d0f3f81ac723abe5347bb6cb88eed6a65243c63f996b2f00a007e99f3e8559a11bdb1125fe4f6d7aaaf906f5adb09e22b7d7ba60cddd448fa74e714824e27de361d1efca94dc58bd29550a5ee8830c0b42da0d177054166c6698771d8ebb7cff535ff4b1821039ccc17601bc356784459395c06a33322e1c9289f2e4284938d0f3f81ac723abe5347bb6cb88eed6a65243c63f996b2f00a007e99f3e8559a11bdb1125fe4f6d7aaaf906f5adb09e22b7d7ba60cddd448fa74e714824e27de361d1efc";
        let expected_decoded_hex = "02000000b164bf1b97bb9f4bb472e89f5b1484f25209c9d9343e92ba09dd9d52";

        let obf = Obfuscator::new(key.to_vec(), 4, 0);
        let mut buf = hex_to_bytes(encoded_hex);
        let ok = obf.decode(&mut buf);
        assert!(ok, "decode must succeed");
        assert_eq!(bytes_to_hex(&buf), expected_decoded_hex);
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let key = b"my-test-secret-key-32-bytes-long";
        let obf = Obfuscator::new(key.to_vec(), 16, 0);

        // Simulated WireGuard Data packet: Type=4, followed by 3 zeros, followed by 60 random bytes
        let mut original = vec![4u8, 0, 0, 0];
        original.extend_from_slice(&[0x42; 60]);

        let mut packet = original.clone();
        obf.encode(&mut packet);

        // Encoded packet must be modified (header masked, dummy added, XORed)
        assert_ne!(packet, original);

        let ok = obf.decode(&mut packet);
        assert!(ok, "decode must succeed");
        assert_eq!(packet, original, "decoded packet must match original");
    }
}
