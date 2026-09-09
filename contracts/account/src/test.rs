#![cfg(test)]
extern crate std;

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use soroban_sdk::{vec, BytesN, Env, IntoVal};

use crate::{Contract, ContractClient, Error};

/// secp256k1 group order, big-endian.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Derive the Ethereum address for a secp256k1 signing key.
fn eth_address(key: &SigningKey) -> [u8; 20] {
    let pubkey = key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&pubkey.as_bytes()[1..65]);
    hash[12..32].try_into().unwrap()
}

/// Compute the EIP-191 digest that `personal_sign` produces for the
/// 66-character ASCII message "0x" || lowercase_hex(payload).
fn eip191_digest(payload: &[u8; 32]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut msg = std::vec::Vec::with_capacity(30 + 66);
    msg.extend_from_slice(b"\x19Ethereum Signed Message:\n660x");
    for b in payload {
        msg.push(HEX[(b >> 4) as usize]);
        msg.push(HEX[(b & 0x0f) as usize]);
    }
    Keccak256::digest(&msg).into()
}

/// Sign the payload the way an EVM wallet's `personal_sign` would, returning
/// the 65-byte r || s || v signature with v in {0, 1}.
fn sign(env: &Env, key: &SigningKey, payload: &BytesN<32>) -> BytesN<65> {
    let digest = eip191_digest(&payload.to_array());
    let (sig, recovery_id) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = recovery_id.to_byte();
    BytesN::from_array(env, &out)
}

fn check_auth(env: &Env, account: &soroban_sdk::Address, payload: &BytesN<32>, signature: &BytesN<65>) -> Result<(), Result<Error, soroban_sdk::InvokeError>> {
    env.try_invoke_contract_check_auth::<Error>(account, payload, signature.into_val(env), &vec![env])
}

#[test]
fn test_constructor_and_getter() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));

    let account_id = env.register(Contract, (eth.clone(),));
    let client = ContractClient::new(&env, &account_id);

    assert_eq!(client.eth_address(), eth);
}

#[test]
fn test_check_auth_valid_signature() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let signature = sign(&env, &key, &payload);

    assert_eq!(check_auth(&env, &account_id, &payload, &signature), Ok(()));
}

/// Signatures with the legacy v encoding (27/28) are accepted too.
#[test]
fn test_check_auth_valid_signature_legacy_v() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let mut sig = sign(&env, &key, &payload).to_array();
    sig[64] += 27;
    let signature = BytesN::from_array(&env, &sig);

    assert_eq!(check_auth(&env, &account_id, &payload, &signature), Ok(()));
}

/// Different payloads produce different digests, so both signatures verify
/// only against their own payload.
#[test]
fn test_check_auth_distinct_payloads() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload_a = BytesN::from_array(&env, &[1u8; 32]);
    let payload_b = BytesN::from_array(&env, &[2u8; 32]);
    let sig_a = sign(&env, &key, &payload_a);
    let sig_b = sign(&env, &key, &payload_b);

    assert_eq!(check_auth(&env, &account_id, &payload_a, &sig_a), Ok(()));
    assert_eq!(check_auth(&env, &account_id, &payload_b, &sig_b), Ok(()));
    assert_eq!(check_auth(&env, &account_id, &payload_a, &sig_b), Err(Ok(Error::WrongSigner)));
    assert_eq!(check_auth(&env, &account_id, &payload_b, &sig_a), Err(Ok(Error::WrongSigner)));
}

/// A valid signature from a different key recovers a different address.
#[test]
fn test_check_auth_wrong_signer() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let other_key = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let signature = sign(&env, &other_key, &payload);

    assert_eq!(check_auth(&env, &account_id, &payload, &signature), Err(Ok(Error::WrongSigner)));
}

/// A signature over a different payload than the one being checked fails.
#[test]
fn test_check_auth_tampered_payload() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let signature = sign(&env, &key, &payload);
    let tampered = BytesN::from_array(&env, &[43u8; 32]);

    assert_eq!(check_auth(&env, &account_id, &tampered, &signature), Err(Ok(Error::WrongSigner)));
}

/// A tampered signature (bit flipped in r) fails.
#[test]
fn test_check_auth_tampered_signature() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let mut sig = sign(&env, &key, &payload).to_array();
    sig[0] ^= 0x01;
    let signature = BytesN::from_array(&env, &sig);

    assert!(check_auth(&env, &account_id, &payload, &signature).is_err());
}

/// v values outside {0, 1, 27, 28} — including EIP-155 encodings — are rejected.
#[test]
fn test_check_auth_invalid_recovery_id() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let sig = sign(&env, &key, &payload).to_array();

    for v in [2u8, 3, 26, 29, 37, 38, 255] {
        let mut bad = sig;
        bad[64] = v;
        let signature = BytesN::from_array(&env, &bad);
        assert_eq!(check_auth(&env, &account_id, &payload, &signature), Err(Ok(Error::InvalidRecoveryId)), "v = {v}");
    }
}

/// The malleable high-s counterpart of a valid signature is rejected before
/// key recovery.
#[test]
fn test_check_auth_high_s() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));

    let payload = BytesN::from_array(&env, &[42u8; 32]);
    let sig = sign(&env, &key, &payload).to_array();

    // s' = N - s, v' = v ^ 1: same digest recovers the same key, but the
    // signature is non-canonical and must be rejected.
    let mut high = sig;
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let n = SECP256K1_N[i] as i16;
        let s = sig[32 + i] as i16 + borrow as i16;
        let d = n - s;
        high[32 + i] = (d & 0xff) as u8;
        borrow = if d < 0 { 1 } else { 0 };
    }
    assert_eq!(borrow, 0);
    high[64] ^= 1;
    let signature = BytesN::from_array(&env, &high);

    assert_eq!(check_auth(&env, &account_id, &payload, &signature), Err(Ok(Error::NonCanonicalSignature)));
}

/// `extend` is callable by anyone and does not panic.
#[test]
fn test_extend() {
    let env = Env::default();
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let account_id = env.register(Contract, (eth,));
    let client = ContractClient::new(&env, &account_id);

    client.extend();
}
