use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use udp_obfs::aes::{AES, BUFSIZE};
use aes_gcm::aead::heapless;
use rand::{thread_rng, RngCore, Rng};

pub fn aes_enc_bench(c: &mut Criterion) {
    let aes = AES::new(b"this is my key..");

    c.bench_function("aes-gcm-128 enc", 
        |b| b.iter_batched(|| {
                let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();

                let n = 1420;
                buf.resize(n, 0).expect("could not resize buf");
                thread_rng().fill_bytes(&mut buf[..n]);

                (buf, thread_rng().gen::<u64>())
            }, 
            |(mut buf, counter)| { black_box(aes.encrypt(black_box(counter), black_box(&mut buf))); }, 
            BatchSize::SmallInput
        )
    );
}

pub fn aes_dec_bench(c: &mut Criterion) {
    let aes = AES::new(b"this is my key..");

    let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();

    c.bench_function("aes-gcm-128 dec", 
        |b| b.iter_batched(|| {
                buf.clear();
                let n = 1420;
                buf.resize(n, 0).expect("could not resize buf");
                thread_rng().fill_bytes(&mut buf[..n]);

                let counter = thread_rng().gen();
                let ciphertext = aes.encrypt(counter, &mut buf);

                let mut buf: heapless::Vec<u8, BUFSIZE> = heapless::Vec::new();
                buf.extend_from_slice(&ciphertext[..]).unwrap();

                buf
            }, 
            |mut buf| { black_box(aes.decrypt(black_box(&mut buf))).expect("could not decrypt"); }, 
            BatchSize::SmallInput
        )
    );
}

criterion_group!(benches, aes_enc_bench, aes_dec_bench);
criterion_main!(benches);
