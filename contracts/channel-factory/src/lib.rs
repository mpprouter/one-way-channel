//! # Channel Factory
//!
//! A factory contract for opening channel contracts on Soroban (Stellar).
//!
//! The factory stores a channel contract wasm hash and opens new channel
//! instances using it. An admin can update the wasm hash to open newer
//! versions of the channel contract.
//!
//! ## Functions
//!
//! | Function | Description |
//! |---|---|
//! | `__constructor` | Initialize the factory with an admin and channel wasm hash. |
//! | `set_wasm` | Update the stored channel wasm hash. Admin only. |
//! | `open` | Deploy a new channel contract with the given parameters. The caller passes the expected channel wasm hash, which must match the stored one. |
//! | `admin` | Returns the admin address. |
//! | `wasm_hash` | Returns the stored channel wasm hash. |
//! | `extend` | Extend the lifetime (TTL) of the factory's storage. |
//!
//! ## Storage lifetime
//!
//! `open`, `set_wasm`, and `extend` extend the factory's instance TTL. A
//! factory left idle for a long period can still be archived; it must then
//! be restored before use. Deployed channels do not depend on the factory.

#![no_std]
use soroban_sdk::{assert_with_error, contract, contracterror, contractevent, contractimpl, contracttype, xdr::ToXdr, Address, BytesN, Env};

/// Approximate number of ledgers per day, assuming 5 second ledger close times.
const LEDGERS_PER_DAY: u32 = 17280;
/// When the instance storage TTL drops below this threshold, extend it.
const TTL_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
/// The TTL to extend the instance storage to.
const TTL_EXTEND_TO: u32 = 60 * LEDGERS_PER_DAY;

/// Emitted when the admin changes the channel wasm hash used for future
/// deployments. Existing channels are unaffected.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmSet {
    /// The new channel wasm hash.
    pub wasm_hash: BytesN<32>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    WasmHashMismatch = 1,
}

#[contracttype]
pub enum DataKey {
    Admin,
    WasmHash,
}

#[contract]
pub struct FactoryContract;

#[contracttype]
struct DeploymentSaltPreimage(Address, BytesN<32>);

#[contractimpl]
impl FactoryContract {
    /// Initialize the factory with an admin and a channel contract wasm hash.
    ///
    /// Callable by the opener.
    ///
    /// # Auth
    /// None.
    pub fn __constructor(env: &Env, admin: Address, wasm_hash: BytesN<32>) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::WasmHash, &wasm_hash);
    }

    /// Returns the admin address.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn admin(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Returns the stored channel contract wasm hash.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn wasm_hash(env: &Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::WasmHash).unwrap()
    }

    /// Update the stored channel contract wasm hash.
    ///
    /// Callable by the admin.
    ///
    /// # Auth
    /// - `admin`: required.
    pub fn set_wasm(env: &Env, wasm_hash: BytesN<32>) {
        // Verify the admin.
        let admin = Self::admin(env);
        admin.require_auth();
        Self::extend_instance_ttl(env);

        env.storage().instance().set(&DataKey::WasmHash, &wasm_hash);
        env.events().publish_event(&WasmSet { wasm_hash });
    }

    /// Extend the lifetime (TTL) of the factory's instance storage.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn extend(env: &Env) {
        Self::extend_instance_ttl(env);
    }

    /// Deploy a new channel.
    ///
    /// `wasm_hash` must equal the factory's stored channel wasm hash. Because
    /// it is part of the invocation the funder authorizes, the funder's
    /// signature pins the exact channel implementation that gets deployed;
    /// an admin `set_wasm` between signing and submission makes the call fail
    /// instead of silently deploying different code.
    ///
    /// Callable by anyone, authorized by the funder (from).
    ///
    /// # Auth
    /// - `from`: required.
    pub fn open(env: &Env, salt: BytesN<32>, wasm_hash: BytesN<32>, token: Address, from: Address, commitment_key: BytesN<32>, to: Address, amount: i128, refund_waiting_period: u32) -> Address {
        // Authorize the funder at the factory level so that the channel
        // constructor's top_up does not require non-root authorization.
        from.require_auth();

        // The funder's authorization must name the implementation deployed.
        assert_with_error!(env, wasm_hash == Self::wasm_hash(env), Error::WasmHashMismatch);
        Self::extend_instance_ttl(env);
        let deployment_salt: BytesN<32> = env.crypto().sha256(&DeploymentSaltPreimage(from.clone(), salt).to_xdr(env)).into();
        let channel_address = env
            .deployer()
            .with_current_contract(deployment_salt)
            .deploy_v2(wasm_hash, (token, from, commitment_key, to, amount, refund_waiting_period));

        channel_address
    }
}

impl FactoryContract {
    fn extend_instance_ttl(env: &Env) {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}

mod test;
