use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use udp_obfs::aes::{AES, NONCELEN};
use rand::{thread_rng, RngCore, Rng};

pub fn aes_enc_bench(c: &mut Criterion) {
    let aes = AES::new(b"this is my key..");
    let mut to = [0u8; NONCELEN+1500+16];
    
    c.bench_function("aes-gcm-128 enc", 
        |b| b.iter_batched(|| {
                let counter = thread_rng().gen();
                let mut buf = [0u8; 1500];
                thread_rng().fill_bytes(&mut buf[..]);
                (buf, counter)
            }, 
            |(buf, counter)| { black_box(aes.encrypt(black_box(counter), black_box(&buf[..]), black_box(&mut to[..]))); }, 
            BatchSize::SmallInput
        )
    );
}

pub fn aes_dec_bench(c: &mut Criterion) {
    let aes = AES::new(b"this is my key..");
    let mut to = [0u8; NONCELEN+1500+16];

    c.bench_function("aes-gcm-128 dec", 
        |b| b.iter_batched(|| {
                let counter = thread_rng().gen();
                let mut buf = [0u8; 1500];
                thread_rng().fill_bytes(&mut buf[..]);
                let send = aes.encrypt(counter, &buf[..], &mut to[..]);
                let mut msg = [0u8; NONCELEN+1500+16];
                msg.copy_from_slice(&send[..]);
                msg
            }, 
            |msg| { black_box(aes.decrypt(black_box(&msg[..]))).expect("could not decrypt"); }, 
            BatchSize::SmallInput
        )
    );
}

criterion_group!(benches, aes_enc_bench, aes_dec_bench);
criterion_main!(benches);
