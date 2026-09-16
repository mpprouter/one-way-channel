//! # Account
//!
//! A custom account contract for Soroban (Stellar) controlled by an EVM
//! (secp256k1) wallet key, such as a MetaMask account on Base or Ethereum.
//!
//! > [!WARNING]
//! > **The contracts in this repository have not been audited.**
//!
//! The contract stores a single 20-byte Ethereum address. Any Soroban
//! invocation that requires this account's authorization is approved by a
//! `personal_sign` (EIP-191) signature from the corresponding EVM key over
//! the Soroban authorization payload. This lets a user whose only key is an
//! EVM browser wallet act as a first-class Soroban address — for example as
//! the funder (`from`) of a payment channel — with no Stellar key at all.
//!
//! Replay protection, nonces, expiration, and network binding are provided
//! by the Soroban authorization framework, which computes the 32-byte
//! `signature_payload` over the full invocation tree. This contract only
//! verifies that the payload was signed by the stored EVM address.
//!
//! ## Signed message format
//!
//! The wallet signs the 66-character ASCII string `m = "0x" || lowercase_hex(payload)`
//! via `personal_sign`. The contract rebuilds `m` from the payload and verifies:
//!
//! ```text
//! digest = keccak256("\x19Ethereum Signed Message:\n66" || m)
//! ecrecover(digest, signature) == stored ethereum address
//! ```
//!
//! Note for SDKs: providers interpret a `0x`-prefixed `personal_sign` param as
//! hex data and sign the *decoded* bytes. To sign the 66 ASCII bytes of `m`,
//! pass `"0x" || hex(utf8_bytes(m))` (132 hex chars) at the RPC layer.
//!
//! Signatures must be 65 bytes `r || s || v` with canonical low `s` and
//! `v` in {0, 1, 27, 28}. Only externally owned accounts are supported;
//! contract wallets (ERC-1271) cannot be verified.
//!
//! ## Functions
//!
//! | Function | Description |
//! |---|---|
//! | `__constructor` | Store the controlling Ethereum address. Immutable thereafter. |
//! | `__check_auth` | Verify an EIP-191 signature over the authorization payload. |
//! | `eth_address` | Returns the controlling Ethereum address. |
//! | `extend` | Extend the lifetime (TTL) of the account's storage. |

#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Bytes, BytesN, Env, Vec,
};

/// Approximate number of ledgers per day, assuming 5 second ledger close times.
const LEDGERS_PER_DAY: u32 = 17280;
/// When the instance storage TTL drops below this threshold, extend it.
const TTL_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
/// The TTL to extend the instance storage to.
const TTL_EXTEND_TO: u32 = 60 * LEDGERS_PER_DAY;

/// secp256k1 group order halved, big-endian: signatures with s above this
/// value are non-canonical and rejected.
const SECP256K1_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    InvalidRecoveryId = 1,
    NonCanonicalSignature = 2,
    WrongSigner = 3,
}

#[contracttype]
pub enum DataKey {
    EthAddress,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    /// Store the controlling Ethereum address. Immutable thereafter.
    ///
    /// Callable by the deployer.
    ///
    /// # Auth
    /// None. Deployment integrity is the deployer's responsibility: the
    /// account factory binds the deployed address to the address stored here
    /// by deriving the deployment salt from it.
    pub fn __constructor(env: &Env, eth_address: BytesN<20>) {
        env.storage().instance().set(&DataKey::EthAddress, &eth_address);
    }

    /// Returns the controlling Ethereum address.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn eth_address(env: &Env) -> BytesN<20> {
        env.storage().instance().get(&DataKey::EthAddress).unwrap()
    }

    /// Extend the lifetime (TTL) of the account's instance storage, so that
    /// a long-lived account is not archived while in use. Extension also
    /// happens as a side effect of `__check_auth`.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn extend(env: &Env) {
        Self::extend_instance_ttl(env);
    }
}

#[contractimpl]
impl CustomAccountInterface for Contract {
    type Signature = BytesN<65>;
    type Error = Error;

    /// Verify an EIP-191 `personal_sign` signature over the Soroban
    /// authorization payload.
    ///
    /// The authorization contexts are intentionally not restricted: this
    /// account may authorize any Soroban invocation, which is what makes a
    /// permissionless exit (e.g. withdrawing channel funds to any address)
    /// possible without this contract enumerating destinations.
    fn __check_auth(env: Env, signature_payload: Hash<32>, signature: BytesN<65>, _auth_contexts: Vec<Context>) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);

        let sig = signature.to_array();

        // Normalize the recovery id: accept v in {0, 1, 27, 28}.
        let recovery_id: u32 = match sig[64] {
            0 | 27 => 0,
            1 | 28 => 1,
            _ => return Err(Error::InvalidRecoveryId),
        };

        // Reject non-canonical (high-s) signatures.
        let s: &[u8; 32] = sig[32..64].try_into().unwrap();
        if s > &SECP256K1_N_HALF {
            return Err(Error::NonCanonicalSignature);
        }

        // digest = keccak256("\x19Ethereum Signed Message:\n66" || "0x" || hex(payload))
        let mut message = Bytes::from_slice(&env, b"\x19Ethereum Signed Message:\n660x");
        append_hex(&mut message, &signature_payload.to_bytes().to_array());
        let digest = env.crypto().keccak256(&message);

        // Recover the uncompressed public key (0x04 || x || y) and derive the
        // Ethereum address from it.
        let rs: BytesN<64> = BytesN::from_array(&env, sig[0..64].try_into().unwrap());
        let public_key = env.crypto().secp256k1_recover(&digest, &rs, recovery_id);
        let public_key_hash = env.crypto().keccak256(&Bytes::from_slice(&env, &public_key.to_array()[1..65])).to_bytes();
        let recovered: BytesN<20> = BytesN::from_array(&env, public_key_hash.to_array()[12..32].try_into().unwrap());

        if recovered != Self::eth_address(&env) {
            return Err(Error::WrongSigner);
        }
        Ok(())
    }
}

impl Contract {
    fn extend_instance_ttl(env: &Env) {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}

/// Append the lowercase hex encoding of the given bytes.
fn append_hex(out: &mut Bytes, bytes: &[u8; 32]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push_back(HEX[(b >> 4) as usize]);
        out.push_back(HEX[(b & 0x0f) as usize]);
    }
}

mod test;
