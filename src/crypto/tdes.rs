//! Triple-DES (3DES) algorithms.
use {
    cipher::{
        block_padding::NoPadding, BlockDecrypt as _, BlockDecryptMut as _, BlockEncrypt as _,
        BlockEncryptMut as _, InnerIvInit as _, KeyInit as _,
    },
    des::{Des, TdesEde2},
    sha1::{Digest, Sha1},
};

pub fn set_parity_bits(key: &mut [u8]) {
    for byte in key {
        *byte &= 0xFE;
        *byte |= 1 ^ (byte.count_ones() as u8 & 1);
    }
}

pub fn seed_from_mrz(mrz: &str) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(mrz.as_bytes());
    let hash = hasher.finalize();
    hash[0..16].try_into().unwrap()
}

pub fn derive_keys(seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    (derive_key(seed, 1), derive_key(seed, 2))
}

pub fn derive_key(seed: &[u8; 16], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    let mut key: [u8; 16] = hash[0..16].try_into().unwrap();
    set_parity_bits(&mut key);
    key
}

/// Retail MAC (ISO 9797-1 mode 3) using DES.
// See <https://crypto.stackexchange.com/questions/18951/what-are-options-to-compute-des-retail-mac-aka-iso-9797-1-mode-3-under-pkcs11>
pub fn mac_3des(key: &[u8; 16], msg: &[u8]) -> [u8; 8] {
    let des1 = Des::new_from_slice(&key[..8]).unwrap();
    let des2 = Des::new_from_slice(&key[8..]).unwrap();
    let mut state = [0_u8; 8];
    for block in msg.chunks(8) {
        for i in 0..block.len() {
            state[i] ^= block[i];
        }
        if block.len() < 8 {
            state[block.len()] ^= 0x80;
        }
        des1.encrypt_block((&mut state).into());
    }
    if msg.len() % 8 == 0 {
        state[0] ^= 0x80;
        des1.encrypt_block((&mut state).into());
    }
    des2.decrypt_block((&mut state).into());
    des1.encrypt_block((&mut state).into());
    state
}

pub fn enc_3des(key: &[u8; 16], msg: &mut [u8]) {
    assert!(msg.len() % 8 == 0);

    let cipher = TdesEde2::new_from_slice(key).unwrap();
    let iv = [0; 8];
    let block_mode = cbc::Encryptor::inner_iv_slice_init(cipher, &iv).unwrap();

    let len = msg.len();
    block_mode
        .encrypt_padded_mut::<NoPadding>(msg, len)
        .unwrap();
}

pub fn dec_3des(key: &[u8; 16], msg: &mut [u8]) {
    assert!(msg.len() % 8 == 0);

    let cipher = TdesEde2::new_from_slice(key).unwrap();
    let iv = [0; 8];
    let block_mode = cbc::Decryptor::inner_iv_slice_init(cipher, &iv).unwrap();
    block_mode.decrypt_padded_mut::<NoPadding>(msg).unwrap();
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    /// Example from ICAO 9303-11 section D.2
    #[test]
    fn test_bac_example() {
        let mrz = "L898902C<369080619406236";
        let seed = seed_from_mrz(mrz);
        assert_eq!(seed, hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

        let (kenc, kmac) = derive_keys(&seed);
        assert_eq!(kenc, hex!("AB94FDECF2674FDFB9B391F85D7F76F2"));
        assert_eq!(kmac, hex!("7962D9ECE03D1ACD4C76089DCE131543"));
    }

    // Example from ICAO 9303-11 section D.2
    #[test]
    fn test_derive_keys() {
        let k_seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let (kenc, kmac) = derive_keys(&k_seed);
        assert_eq!(kenc, hex!("979EC13B1CBFE9DCD01AB0FED307EAE5"));
        assert_eq!(kmac, hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"));
    }

    #[test]
    fn test_mac_3des() {
        let key = hex!("7962D9ECE03D1ACD4C76089DCE131543");
        let msg = hex!("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2");
        let mac = hex!("5F1448EEA8AD90A7");
        assert_eq!(mac_3des(&key, &msg), mac);

        let key = hex!("7962D9ECE03D1ACD4C76089DCE131543");
        let msg = hex!("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F");
        let mac = hex!("2F2D235D074D7449");
        assert_eq!(mac_3des(&key, &msg), mac);

        let key = hex!("F1CB1F1FB5ADF208806B89DC579DC1F8");
        let msg = hex!("887022120C06C2270CA4020C800000008709016375432908C044F6");
        let mac = hex!("BF8B92D635FF24F8");
        assert_eq!(mac_3des(&key, &msg), mac);
    }

    #[test]
    fn test_enc_3des() {
        let key = hex!("AB94FDECF2674FDFB9B391F85D7F76F2");
        let msg = hex!("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B");
        let enc = hex!("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2");
        let mut res = msg;
        enc_3des(&key, &mut res[..]);
        assert_eq!(res, enc);

        let key = hex!("AB94FDECF2674FDFB9B391F85D7F76F2");
        let msg = hex!("4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B");
        let enc = hex!("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F");
        let mut res = msg;
        enc_3des(&key, &mut res[..]);
        assert_eq!(res, enc);

        let key = hex!("979EC13B1CBFE9DCD01AB0FED307EAE5");
        let msg = hex!("011E800000000000");
        let enc = hex!("6375432908C044F6");
        let mut res = msg;
        enc_3des(&key, &mut res[..]);
        assert_eq!(res, enc);
    }
}
