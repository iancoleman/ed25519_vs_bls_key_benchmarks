use ed25519_dalek::{Keypair, Signer};
use rand::RngCore;
use rand::thread_rng;
use rand::prelude::ThreadRng;
use sha2::{Digest, Sha512};
use tiny_keccak::{Hasher, Sha3};
use time::precise_time_ns;

use blst::min_sig::SecretKey as BlstSecretKey;
use threshold_crypto::SecretKey as TcSecretKey;

const NUM_TESTS: usize = 1000;

struct Result {
    heading: String,
    values: [f64; NUM_TESTS],
}

fn main() {
    let mut results = vec![];
    // do tests and get results
    results.push(sign_bls_threshold_crypto("BLS TC Sign 32B (µs)".to_string(), 32));
    results.push(sign_bls_threshold_crypto("BLS TC Sign 1MiB (µs)".to_string(), 1024*1024));
    results.push(sign_bls_blst("BLS BLST Sign 32B (µs)".to_string(), 32));
    results.push(sign_bls_blst("BLS BLST Sign 1MiB (µs)".to_string(), 1024*1024));
    results.push(sign_ed25519("ED25519 Sign 32B (µs)".to_string(), 32));
    results.push(sign_ed25519("ED25519 Sign 1MiB (µs)".to_string(), 1024*1024));
    results.push(verify_bls_threshold_crypto("BLS TC Verify 32B (µs)".to_string(), 32));
    results.push(verify_bls_threshold_crypto("BLS TC Verify 1MiB (µs)".to_string(), 1024*1024));
    results.push(verify_bls_blst("BLS BLST Verify 32B (µs)".to_string(), 32));
    results.push(verify_bls_blst("BLS BLST Verify 1MiB (µs)".to_string(), 1024*1024));
    results.push(verify_ed25519("ED25519 Verify 32B (µs)".to_string(), 32));
    results.push(verify_ed25519("ED25519 Verify 1MiB (µs)".to_string(), 1024*1024));
    results.push(sha2_512("SHA2-512 32B (µs)".to_string(), 32));
    results.push(sha2_512("SHA2-512 1MiB (µs)".to_string(), 1024*1024));
    results.push(sha3_256("SHA3-256 32B (µs)".to_string(), 32));
    results.push(sha3_256("SHA3-256 1MiB (µs)".to_string(), 1024*1024));
    // show results
    // headings
    let results_headings: Vec<String> = results.iter().map(|r| r.heading.clone()).collect();
    let mut headings: Vec<String> = vec!["".to_string()];
    headings.extend(results_headings);
    println!("{}", headings.join(","));
    // averages
    let averages = [
        "Average",
        "=AVERAGE(B5:B1004)",
        "=AVERAGE(C5:C1004)",
        "=AVERAGE(D5:D1004)",
        "=AVERAGE(E5:E1004)",
        "=AVERAGE(F5:F1004)",
        "=AVERAGE(G5:G1004)",
        "=AVERAGE(H5:H1004)",
        "=AVERAGE(I5:I1004)",
        "=AVERAGE(J5:J1004)",
        "=AVERAGE(K5:K1004)",
        "=AVERAGE(L5:L1004)",
        "=AVERAGE(M5:M1004)",
    ];
    println!("{}", averages.join(","));
    // medians
    let medians = [
        "Median",
        "=MEDIAN(B5:B1004)",
        "=MEDIAN(C5:C1004)",
        "=MEDIAN(D5:D1004)",
        "=MEDIAN(E5:E1004)",
        "=MEDIAN(F5:F1004)",
        "=MEDIAN(G5:G1004)",
        "=MEDIAN(H5:H1004)",
        "=MEDIAN(I5:I1004)",
        "=MEDIAN(J5:J1004)",
        "=MEDIAN(K5:K1004)",
        "=MEDIAN(L5:L1004)",
        "=MEDIAN(M5:M1004)",
    ];
    println!("{}", medians.join(","));
    // stdevs
    let stdevs = [
        "stdev",
        "=STDEV(B5:B1004)",
        "=STDEV(C5:C1004)",
        "=STDEV(D5:D1004)",
        "=STDEV(E5:E1004)",
        "=STDEV(F5:F1004)",
        "=STDEV(G5:G1004)",
        "=STDEV(H5:H1004)",
        "=STDEV(I5:I1004)",
        "=STDEV(J5:J1004)",
        "=STDEV(K5:K1004)",
        "=STDEV(L5:L1004)",
        "=STDEV(M5:M1004)",
    ];
    println!("{}", stdevs.join(","));
    // values
    for i in 0..NUM_TESTS {
        let mut params: Vec<f64> = vec![];
        params.push(i as f64 + 1.0);
        for j in 0..results.len() {
            params.push(results[j].values[i]);
        }
        let params_row: Vec<String> = params.iter().map(|p| p.to_string()).collect();
        println!("{}", params_row.join(","));
    }
}

fn sign_bls_threshold_crypto(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let bls_sk = TcSecretKey::random();
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let before = precise_time_ns();
        let _sig = bls_sk.sign(msg);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

fn sign_bls_blst(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        // blst
        let mut ikm = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlstSecretKey::key_gen(&ikm, &[]).unwrap();
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let before = precise_time_ns();
        let _sig = bls_sk.sign(&msg, dst, &[]);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

fn sign_ed25519(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let mut csprng: ThreadRng = thread_rng();
        let kp = Keypair::generate(&mut csprng);
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let before = precise_time_ns();
        let _sig = kp.sign(&msg);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

fn verify_bls_threshold_crypto(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let bls_sk = TcSecretKey::random();
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let sig = bls_sk.sign(&msg);
        let before = precise_time_ns();
        let _verified = bls_sk.public_key().verify(&sig, &msg);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

fn verify_bls_blst(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let mut ikm = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlstSecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = bls_sk.sk_to_pk();
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = bls_sk.sign(&msg, dst, &[]);
        let before = precise_time_ns();
        let _verified = sig.verify(&msg, dst, &[], &pk);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

fn verify_ed25519(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let mut csprng: ThreadRng = thread_rng();
        let kp = Keypair::generate(&mut csprng);
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let sig = kp.sign(&msg);
        let before = precise_time_ns();
        let _verified = kp.verify(&msg, &sig);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

// used by ed25519-dalek sign
// https://github.com/dalek-cryptography/ed25519-dalek/blob/master/src/secret.rs#L406
fn sha2_512(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let mut h = Sha512::new();
        let before = precise_time_ns();
        h.update(&msg);
        let _hash = h.finalize();
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}

// used by threshold_crypto sign
// https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/util.rs#L3
fn sha3_256(heading: String, msg_len: usize) -> Result {
    let mut result = Result{
        heading: heading,
        values: [0_f64; NUM_TESTS],
    };
    for i in 0..NUM_TESTS {
        let mut msg = vec![0u8; msg_len];
        rand::thread_rng().fill_bytes(&mut msg);
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];
        let before = precise_time_ns();
        sha3.update(&msg);
        sha3.finalize(&mut output);
        let d = precise_time_ns() - before;
        result.values[i] = d as f64 / 1000.0;
    }
    result
}
