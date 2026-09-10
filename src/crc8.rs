// CRC-8 table and stream XOR cipher matching Phobos obfuscation.h

pub const MAX_XOR_KEY_LENGTH: usize = 256;

/// Generates the Dallas/Maxim CRC-8 lookup table (polynomial 0x8C / reflected 0x31).
pub fn init_crc8_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    for i in 0..256 {
        let mut crc = 0u8;
        let mut inbyte = i as u8;
        for _ in 0..8 {
            let mix = (crc ^ inbyte) & 0x01;
            crc >>= 1;
            if mix != 0 {
                crc ^= 0x8C;
            }
            inbyte >>= 1;
        }
        table[i] = crc;
    }
    table
}

pub static CRC8_TABLE: std::sync::LazyLock<[u8; 256]> = std::sync::LazyLock::new(init_crc8_table);

/// Applies the Phobos XOR stream cipher in-place to `buffer`.
///
/// Matching C implementation:
/// base = (uint8_t)(length + key_length)
/// key_adj[k] = key[k] + base
/// crc = 0
/// for i in 0..length:
///   crc = table[crc ^ key_adj[ki]]
///   buffer[i] ^= crc
///   if ++ki >= key_length { ki = 0 }
pub fn xor_data(buffer: &mut [u8], key: &[u8]) {
    if buffer.is_empty() || key.is_empty() {
        return;
    }
    let table = &*CRC8_TABLE;
    let key_len = key.len().min(MAX_XOR_KEY_LENGTH);
    let key = &key[..key_len];

    let base = (buffer.len() + key_len) as u8;
    let mut key_adj = [0u8; MAX_XOR_KEY_LENGTH];
    for k in 0..key_len {
        key_adj[k] = key[k].wrapping_add(base);
    }

    let mut crc = 0u8;
    let mut ki = 0usize;
    for b in buffer.iter_mut() {
        crc = table[(crc ^ key_adj[ki]) as usize];
        *b ^= crc;
        ki += 1;
        if ki >= key_len {
            ki = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc8_table_known_values() {
        let table = &*CRC8_TABLE;
        assert_eq!(table[0], 0);
        assert_eq!(table[1], 0x5e);
        assert_eq!(table[2], 0xbc);
    }

    #[test]
    fn test_xor_symmetry() {
        let mut data = b"Hello, Phobos WireGuard Obfuscator!".to_vec();
        let original = data.clone();
        let key = b"mysecretkey12345";

        xor_data(&mut data, key);
        assert_ne!(data, original);

        xor_data(&mut data, key);
        assert_eq!(data, original);
    }
}
