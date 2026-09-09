#![cfg(test)]
extern crate std;

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    xdr::{
        Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
    },
    Address, Bytes, BytesN, Env, IntoVal, TryFromVal, Val,
};

use crate::{FactoryContract, FactoryContractClient};

mod account_contract {
    use soroban_sdk::auth::Context;
    soroban_sdk::contractimport!(file = "../../target/wasm32v1-none/release/account.wasm");
}

mod channel_factory_contract {
    soroban_sdk::contractimport!(file = "../../target/wasm32v1-none/release/channel_factory.wasm");
}

mod channel_contract {
    soroban_sdk::contractimport!(file = "../../target/wasm32v1-none/release/channel.wasm");
}

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

fn create_token<'a>(env: &Env) -> (Address, TokenClient<'a>, StellarAssetClient<'a>) {
    let admin = Address::generate(env);
    let contract_id = env.register_stellar_asset_contract_v2(admin.clone());
    let address = contract_id.address();
    (address.clone(), TokenClient::new(env, &address), StellarAssetClient::new(env, &address))
}

/// Build an authorized invocation of a single contract function with no
/// sub-invocations.
fn contract_fn(contract: &Address, name: &str, args: std::vec::Vec<ScVal>) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract.try_into().unwrap(),
            function_name: name.try_into().unwrap(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: Default::default(),
    }
}

fn sc_val(env: &Env, v: impl IntoVal<Env, Val>) -> ScVal {
    ScVal::try_from_val(env, &v.into_val(env)).unwrap()
}

/// Build a real (non-mocked) authorization entry for the account: compute the
/// Soroban authorization signature payload exactly as the host will, and sign
/// it the way an EVM wallet's `personal_sign` would.
fn account_auth(env: &Env, key: &SigningKey, account: &Address, nonce: i64, invocation: SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
    let signature_expiration_ledger = env.ledger().sequence() + 100;
    let network_id = env.ledger().get().network_id;
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let payload = env.crypto().sha256(&Bytes::from_slice(env, &preimage.to_xdr(Limits::none()).unwrap())).to_array();

    let digest = eip191_digest(&payload);
    let (sig, recovery_id) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = recovery_id.to_byte();
    let signature = ScVal::Bytes(sig_bytes.to_vec().try_into().unwrap());

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account.try_into().unwrap(),
            nonce,
            signature_expiration_ledger,
            signature,
        }),
        root_invocation: invocation,
    }
}

/// The factory derives the same address for the same Ethereum address, before
/// and after deployment, and different addresses for different signers. The
/// deployed account is bound to the given signer, and re-deployment is
/// rejected.
#[test]
fn test_deterministic_deployment() {
    let env = Env::default();

    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));
    let other_key = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let other_eth = BytesN::from_array(&env, &eth_address(&other_key));

    let wasm_hash = env.deployer().upload_contract_wasm(account_contract::WASM);
    let factory_id = env.register(FactoryContract, (&wasm_hash,));
    let factory_client = FactoryContractClient::new(&env, &factory_id);

    assert_eq!(factory_client.wasm_hash(), wasm_hash);

    // The address is computable before deployment.
    let predicted = factory_client.account_address(&eth);
    let account = factory_client.open_account(&eth);
    assert_eq!(account, predicted);
    assert_eq!(factory_client.account_address(&eth), predicted);

    // The deployed account is controlled by the given Ethereum address.
    let account_client = account_contract::Client::new(&env, &account);
    assert_eq!(account_client.eth_address(), eth);

    // A different signer gets a different address.
    let other_account = factory_client.open_account(&other_eth);
    assert_ne!(other_account, account);

    // Re-deploying an existing account is rejected.
    assert!(factory_client.try_open_account(&eth).is_err());
    factory_client.extend();
}

/// The escape hatch, end to end: an account controlled only by an EVM key is
/// the funder (`from`) of a channel. Using nothing but EVM `personal_sign`
/// signatures over the Soroban authorization payload, the user performs
/// `close_start`, waits out the refund period, calls `refund` (funds land in
/// the account contract), and finally transfers the tokens out of the account
/// to a fresh address. The channel is opened via the channel factory under
/// mocked auth (setup); every exit step runs with real signature verification.
#[test]
fn test_e2e_channel_exit_with_evm_signatures() {
    let env = Env::default();

    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let eth = BytesN::from_array(&env, &eth_address(&key));

    // Deploy the account via the account factory.
    let account_wasm_hash = env.deployer().upload_contract_wasm(account_contract::WASM);
    let account_factory_id = env.register(FactoryContract, (&account_wasm_hash,));
    let account = FactoryContractClient::new(&env, &account_factory_id).open_account(&eth);

    // Set up a channel with the account as funder, via the channel factory.
    let (token_addr, token, asset_admin) = create_token(&env);
    let channel_wasm_hash = env.deployer().upload_contract_wasm(channel_contract::WASM);
    let admin = Address::generate(&env);
    let channel_factory_id = env.register(channel_factory_contract::WASM, (&admin, &channel_wasm_hash));
    let channel_factory_client = channel_factory_contract::Client::new(&env, &channel_factory_id);

    let commitment_key = BytesN::from_array(&env, &[7u8; 32]);
    let to = Address::generate(&env);
    let salt = BytesN::from_array(&env, &[0u8; 32]);
    env.mock_all_auths();
    let channel = channel_factory_client.open(&salt, &channel_wasm_hash, &token_addr, &account, &commitment_key, &to, &0i128, &100u32);
    let channel_client = channel_contract::Client::new(&env, &channel);

    // Deposit: direct token transfer to the channel is permissionless.
    asset_admin.mint(&channel, &500);
    assert_eq!(token.balance(&channel), 500);

    // A signature from the wrong key must not authorize close_start.
    let wrong_key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    env.set_auths(&[account_auth(&env, &wrong_key, &account, 1, contract_fn(&channel, "close_start", std::vec![]))]);
    assert!(channel_client.try_close_start().is_err());

    // close_start, authorized by the real EVM signature.
    env.set_auths(&[account_auth(&env, &key, &account, 2, contract_fn(&channel, "close_start", std::vec![]))]);
    channel_client.close_start();

    // Wait out the refund waiting period.
    env.ledger().with_mut(|l| l.sequence_number += 101);

    // refund, authorized by the real EVM signature: funds land in the account.
    env.set_auths(&[account_auth(&env, &key, &account, 3, contract_fn(&channel, "refund", std::vec![]))]);
    channel_client.refund();
    assert_eq!(token.balance(&channel), 0);
    assert_eq!(token.balance(&account), 500);

    // Transfer out of the account to a fresh address, authorized by the real
    // EVM signature. This is the "withdraw to any address" escape hatch.
    let destination = Address::generate(&env);
    let args = std::vec![sc_val(&env, &account), sc_val(&env, &destination), sc_val(&env, 500i128)];
    env.set_auths(&[account_auth(&env, &key, &account, 4, contract_fn(&token_addr, "transfer", args))]);
    token.transfer(&account, &destination, &500);
    assert_eq!(token.balance(&account), 0);
    assert_eq!(token.balance(&destination), 500);
}
