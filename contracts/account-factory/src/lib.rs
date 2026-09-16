//! # Account Factory
//!
//! A factory contract for deploying account contracts on Soroban (Stellar).
//!
//! > [!WARNING]
//! > **The contracts in this repository have not been audited.**
//!
//! The factory deploys account contracts at deterministic addresses derived
//! from the controlling Ethereum address, so that an account's Soroban
//! address is computable before it is deployed, and so that the deployed
//! address is bound to its signer by construction.
//!
//! There is intentionally no caller-supplied salt and no admin function to
//! change the stored account wasm hash: either would allow an attacker to
//! front-run a deployment and bind a user's computed address to a different
//! signer or different code. A new account wasm version requires deploying a
//! new factory, which derives distinct account addresses.
//!
//! ## Functions
//!
//! | Function | Description |
//! |---|---|
//! | `__constructor` | Initialize the factory with an account contract wasm hash. Immutable thereafter. |
//! | `open_account` | Deploy the account contract for the given Ethereum address. |
//! | `account_address` | Returns the deterministic account address for the given Ethereum address. |
//! | `wasm_hash` | Returns the stored account wasm hash. |
//! | `extend` | Extend the lifetime (TTL) of the factory's storage. |
//!
//! ## Storage lifetime
//!
//! `open_account` and `extend` extend the factory's instance TTL. A factory
//! left idle for a long period can still be archived; it must then be
//! restored before use. Deployed accounts do not depend on the factory, but
//! an account deployed ahead of first use has its own TTL to maintain (see
//! the account contract's `extend`).

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, BytesN, Env, Symbol};

/// Approximate number of ledgers per day, assuming 5 second ledger close times.
const LEDGERS_PER_DAY: u32 = 17280;
/// When the instance storage TTL drops below this threshold, extend it.
const TTL_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
/// The TTL to extend the instance storage to.
const TTL_EXTEND_TO: u32 = 60 * LEDGERS_PER_DAY;

/// Domain separator for the deployment salt derivation, versioned with the
/// account wasm: a future account contract version must use a new domain so
/// its address derivations cannot collide with v1 addresses.
const SALT_DOMAIN: Symbol = symbol_short!("owcacctv1");

#[contracttype]
pub enum DataKey {
    WasmHash,
}

#[contract]
pub struct FactoryContract;

#[contracttype]
struct DeploymentSaltPreimage(Symbol, BytesN<20>);

#[contractimpl]
impl FactoryContract {
    /// Initialize the factory with an account contract wasm hash. Immutable
    /// thereafter.
    ///
    /// Callable by the deployer.
    ///
    /// # Auth
    /// None.
    pub fn __constructor(env: &Env, wasm_hash: BytesN<32>) {
        env.storage().instance().set(&DataKey::WasmHash, &wasm_hash);
    }

    /// Returns the stored account contract wasm hash.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn wasm_hash(env: &Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::WasmHash).unwrap()
    }

    /// Returns the deterministic address at which the account contract for
    /// the given Ethereum address is (or will be) deployed by this factory.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn account_address(env: &Env, eth_address: BytesN<20>) -> Address {
        env.deployer().with_current_contract(Self::deployment_salt(env, &eth_address)).deployed_address()
    }

    /// Deploy the account contract for the given Ethereum address, at the
    /// deterministic address returned by `account_address`. Fails if the
    /// account is already deployed.
    ///
    /// Callable by anyone: the deployed account is controlled solely by the
    /// given Ethereum address, so deploying it on someone else's behalf is
    /// harmless.
    ///
    /// # Auth
    /// None.
    pub fn open_account(env: &Env, eth_address: BytesN<20>) -> Address {
        Self::extend_instance_ttl(env);
        let wasm_hash = Self::wasm_hash(env);
        let account_address = env.deployer().with_current_contract(Self::deployment_salt(env, &eth_address)).deploy_v2(wasm_hash, (eth_address,));

        account_address
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
}

impl FactoryContract {
    fn extend_instance_ttl(env: &Env) {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Derive the deployment salt from the controlling Ethereum address, so
    /// that address ⇔ signer binding is enforced by construction.
    fn deployment_salt(env: &Env, eth_address: &BytesN<20>) -> BytesN<32> {
        env.crypto().sha256(&DeploymentSaltPreimage(SALT_DOMAIN, eth_address.clone()).to_xdr(env)).into()
    }
}

mod test;
