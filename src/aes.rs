use aes_gcm::{Aes128Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use byteorder::{BigEndian, ByteOrder};

pub const NONCELEN: usize = 12;

pub struct AES {
    cipher: Aes128Gcm
}

impl AES {
    pub fn new(key: &[u8]) -> Self {
        let key = Key::clone_from_slice(key);
        return AES{ cipher: Aes128Gcm::new(&key) };
    }

    pub fn encrypt<'a>(&self, counter: u64, buf: &[u8], to: &'a mut [u8]) -> &'a [u8] {
        let mut nonce_bytes = [0u8; NONCELEN];
        BigEndian::write_u64(&mut nonce_bytes, counter);

        let nonce = Nonce::from_slice(&nonce_bytes[..]); // 96 bits, 12 bytes; unique per message

        let ciphertext = self.cipher.encrypt(nonce, &buf[..]).expect("encryption failure!");
        // cipher.encrypt_in_place(nonce, b"", &mut buf).expect("encryption failure!");
        // let buf: Vec<u8> = buf.splice(0..0, nonce_bytes).collect();
        // println!("{}", ciphertext.len());

        to[..NONCELEN].clone_from_slice(&nonce_bytes[..NONCELEN]);
        to[NONCELEN..(NONCELEN+ciphertext.len())].clone_from_slice(&ciphertext);

        &to[..(NONCELEN+ciphertext.len())]
    }

    pub fn decrypt(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, aes_gcm::Error> {
        let nonce_bytes = &msg[..NONCELEN];
        let nonce = Nonce::from_slice(&nonce_bytes); // 96 bits, 12 bytes; unique per message
        self.cipher.decrypt(nonce, &msg[NONCELEN..])
    }
}
