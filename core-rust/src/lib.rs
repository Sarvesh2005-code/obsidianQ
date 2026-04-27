pub mod kem;
pub mod ntt;
pub mod reduce;
pub mod cbd;
pub mod poly;
pub mod polyvec;
pub mod symmetric;
pub mod pack;
pub mod indcpa;

use jni::objects::{JByteBuffer, JClass};
use jni::sys::jint;
use jni::JNIEnv;
use rand_core::OsRng;
use std::panic::{catch_unwind, AssertUnwindSafe};

// Native FFI boundary for Key Generation
#[no_mangle]
pub extern "system" fn Java_com_obsidianq_ObsidianNativeBridge_generateKeyPair(
    env: JNIEnv,
    _class: JClass,
    pk_buffer: JByteBuffer,
    sk_buffer: JByteBuffer,
) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pk_ptr = env.get_direct_buffer_address(&pk_buffer).unwrap_or(std::ptr::null_mut());
        let sk_ptr = env.get_direct_buffer_address(&sk_buffer).unwrap_or(std::ptr::null_mut());

        if pk_ptr.is_null() || sk_ptr.is_null() { return -1; }

        let pk_slice = unsafe { std::slice::from_raw_parts_mut(pk_ptr, kem::KYBER_PUBLICKEYBYTES) };
        let sk_slice = unsafe { std::slice::from_raw_parts_mut(sk_ptr, kem::KYBER_SECRETKEYBYTES) };

        let mut rng = OsRng;
        let (pk, sk) = kem::generate_keypair(&mut rng);

        pk_slice.copy_from_slice(&pk);
        sk_slice.copy_from_slice(&sk.sk);

        0
    }));

    result.unwrap_or(-2)
}

// Native FFI boundary for Encapsulation
#[no_mangle]
pub extern "system" fn Java_com_obsidianq_ObsidianNativeBridge_encapsulateSecret(
    env: JNIEnv,
    _class: JClass,
    pk_buffer: JByteBuffer,
    ct_buffer: JByteBuffer,
    ss_buffer: JByteBuffer,
) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pk_ptr = env.get_direct_buffer_address(&pk_buffer).unwrap_or(std::ptr::null_mut());
        let ct_ptr = env.get_direct_buffer_address(&ct_buffer).unwrap_or(std::ptr::null_mut());
        let ss_ptr = env.get_direct_buffer_address(&ss_buffer).unwrap_or(std::ptr::null_mut());

        if pk_ptr.is_null() || ct_ptr.is_null() || ss_ptr.is_null() { return -1; }

        let pk_slice = unsafe { std::slice::from_raw_parts_mut(pk_ptr, kem::KYBER_PUBLICKEYBYTES) };
        let ct_slice = unsafe { std::slice::from_raw_parts_mut(ct_ptr, kem::KYBER_CIPHERTEXTBYTES) };
        let ss_slice = unsafe { std::slice::from_raw_parts_mut(ss_ptr, 32) };

        let mut pk = [0u8; kem::KYBER_PUBLICKEYBYTES];
        pk.copy_from_slice(pk_slice);

        let mut rng = OsRng;
        let (ct, ss) = kem::encapsulate_key(&pk, &mut rng);

        ct_slice.copy_from_slice(&ct);
        ss_slice.copy_from_slice(&ss.key);

        0
    }));

    result.unwrap_or(-2)
}

// Native FFI boundary for Decapsulation
#[no_mangle]
pub extern "system" fn Java_com_obsidianq_ObsidianNativeBridge_decapsulateSecret(
    env: JNIEnv,
    _class: JClass,
    ct_buffer: JByteBuffer,
    sk_buffer: JByteBuffer,
    ss_buffer: JByteBuffer,
) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let ct_ptr = env.get_direct_buffer_address(&ct_buffer).unwrap_or(std::ptr::null_mut());
        let sk_ptr = env.get_direct_buffer_address(&sk_buffer).unwrap_or(std::ptr::null_mut());
        let ss_ptr = env.get_direct_buffer_address(&ss_buffer).unwrap_or(std::ptr::null_mut());

        if ct_ptr.is_null() || sk_ptr.is_null() || ss_ptr.is_null() { return -1; }

        let ct_slice = unsafe { std::slice::from_raw_parts_mut(ct_ptr, kem::KYBER_CIPHERTEXTBYTES) };
        let sk_slice = unsafe { std::slice::from_raw_parts_mut(sk_ptr, kem::KYBER_SECRETKEYBYTES) };
        let ss_slice = unsafe { std::slice::from_raw_parts_mut(ss_ptr, 32) };

        let mut ct = [0u8; kem::KYBER_CIPHERTEXTBYTES];
        ct.copy_from_slice(ct_slice);
        
        let mut sk = kem::KyberSecretKey { sk: [0u8; kem::KYBER_SECRETKEYBYTES] };
        sk.sk.copy_from_slice(sk_slice);

        let ss = kem::decapsulate_key(&ct, &sk);
        ss_slice.copy_from_slice(&ss.key);

        0
    }));

    result.unwrap_or(-2)
}
