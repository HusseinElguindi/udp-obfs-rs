use aes_gcm::aead::{heapless, AeadInPlace};
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use byteorder::{BigEndian, ByteOrder};

pub const BUFSIZE: usize = 1500;
pub const NONCELEN: usize = 12;

pub struct AES {
    cipher: Aes128Gcm,
}

impl AES {
    pub fn new(key: &[u8]) -> Self {
        let key = Key::<Aes128Gcm>::clone_from_slice(key);
        return AES {
            cipher: Aes128Gcm::new(&key),
        };
    }

    pub fn encrypt<'a>(&self, counter: u64, buf: &'a mut heapless::Vec<u8, BUFSIZE>) -> &'a [u8] {
        let mut nonce_bytes = [0u8; NONCELEN];
        BigEndian::write_u64(&mut nonce_bytes, counter);

        let nonce = Nonce::from_slice(&nonce_bytes[..]); // 96 bits, 12 bytes; unique per message
                                                         // TODO: return error
        self.cipher
            .encrypt_in_place(nonce, b"", buf)
            .expect("encryption failure!");

        buf.extend_from_slice(&nonce_bytes[..NONCELEN])
            .expect("could not extend buf for nonce tag");
        &buf[..]
    }

    pub fn decrypt<'a>(
        &self,
        buf: &'a mut heapless::Vec<u8, BUFSIZE>,
    ) -> std::result::Result<&'a [u8], aes_gcm::Error> {
        let n = buf.len();
        let mut nonce_bytes = [0u8; NONCELEN];
        nonce_bytes.clone_from_slice(&mut buf[(n - NONCELEN)..n]);
        buf.truncate(n - NONCELEN);

        let nonce = Nonce::from_slice(&nonce_bytes); // 96 bits, 12 bytes; unique per message
        self.cipher.decrypt_in_place(nonce, b"", buf)?;

        Ok(&buf[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn encrypt() {
        let aes = AES::new(b"this is my key..");

        let plaintext;
        let ciphertext;
        {
            let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();

            let n = 1420;
            buf.resize(n, 0).expect("could not resize buf");
            thread_rng().fill_bytes(&mut buf[..n]);
            plaintext = buf.to_owned();

            let counter = thread_rng().gen();
            println!("counter: {}", counter);

            ciphertext = aes.encrypt(counter, &mut buf).to_owned();
            println!("ciphertext + nonce len: {}", ciphertext.len());
        }
        assert_ne!(&plaintext[..], &ciphertext[..]);

        let decrypt_text;
        {
            let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
            buf.extend_from_slice(&ciphertext[..]).unwrap();

            decrypt_text = aes.decrypt(&mut buf).unwrap().to_owned();
        }
        assert_eq!(&decrypt_text[..], &plaintext[..]);
    }
}
