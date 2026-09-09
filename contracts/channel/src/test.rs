#![cfg(test)]

use ed25519_dalek::SigningKey;
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _, IssuerFlags, Ledger},
    token::{StellarAssetClient, TokenClient},
    xdr, Address, BytesN, Env, IntoVal, Symbol,
};

use crate::{Commitment, Contract, ContractClient, Error, MAX_REFUND_WAITING_PERIOD};

fn has_event_type(env: &Env, contract: &Address, event_name: &str) -> bool {
    let events = env.events().all().filter_by_contract(contract);
    let target = xdr::ScVal::Symbol(xdr::ScSymbol(event_name.try_into().unwrap()));
    events.events().iter().any(|e| match &e.body {
        xdr::ContractEventBody::V0(body) => body.topics.first() == Some(&target),
    })
}

impl Commitment {
    fn sign(self, signing_key: &SigningKey) -> BytesN<64> {
        use ed25519_dalek::Signer;
        use soroban_sdk::xdr::ToXdr;
        let env = self.channel.env().clone();
        let payload = self.to_xdr(&env);
        let buf = payload.to_buffer::<256>();
        let sig = signing_key.sign(buf.as_slice());
        BytesN::from_array(&env, &sig.to_bytes())
    }
}

fn create_token<'a>(env: &Env) -> (Address, TokenClient<'a>, StellarAssetClient<'a>) {
    let admin = Address::generate(env);
    let contract_id = env.register_stellar_asset_contract_v2(admin.clone());
    let address = contract_id.address();
    (address.clone(), TokenClient::new(env, &address), StellarAssetClient::new(env, &address))
}

/// Settle transfers the committed amount from the channel to the recipient
/// without closing the channel.
#[test]
fn test_settle() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[1u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.settle(&300, &sig);

    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&channel_id), 200);
    assert_eq!(client.withdrawn(), 300);
}

/// Settling with increasing commitment amounts only transfers the
/// incremental difference each time.
#[test]
fn test_settle_incremental() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[2u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    // Settle 200 first.
    let sig1 = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig1);
    assert_eq!(token.balance(&to), 200);
    assert_eq!(client.withdrawn(), 200);

    // Settle 300 total — only 100 more transferred.
    let sig2 = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.settle(&300, &sig2);
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&channel_id), 200);
    assert_eq!(client.withdrawn(), 300);
}

/// Using an older commitment with a lower amount after a higher amount has
/// been settled is a no-op.
#[test]
fn test_settle_older_commitment_no_op() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[16u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    // Settle 300.
    let sig1 = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.settle(&300, &sig1);
    assert_eq!(token.balance(&to), 300);

    // Use an older commitment for 200 — no additional transfer.
    let sig2 = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig2);
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&channel_id), 200);
    assert_eq!(client.withdrawn(), 300);
}

/// Close after settle only transfers the difference.
#[test]
fn test_close_after_settle() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[3u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    // Settle 200 first.
    let sig1 = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig1);
    assert_eq!(token.balance(&to), 200);

    // Close with 500 — only 300 more transferred, remainder refunded to funder.
    let sig2 = Commitment::new(channel_id.clone(), 500).sign(&auth_key);
    client.close(&500, &sig2);
    assert_eq!(token.balance(&to), 500);
    assert_eq!(token.balance(&channel_id), 0);
    assert_eq!(token.balance(&funder), 500);
    assert_eq!(client.withdrawn(), 500);
}

/// Close transfers the difference between committed amount and already
/// withdrawn, and refunds the remainder to the funder.
#[test]
fn test_close() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[4u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig);

    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&channel_id), 0);
    assert_eq!(token.balance(&funder), 700);
}

/// The funder can start closing the channel and refund the full balance after the
/// waiting period elapses.
#[test]
fn test_close_start_and_refund() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[5u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });

    client.refund();
    assert_eq!(token.balance(&funder), 1000);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Refund fails if called before the refund waiting period has elapsed.
#[test]
fn test_refund_too_early() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[6u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    let result = client.try_refund();
    assert!(result.is_err());
}

/// Refund fails if close_start has never been called.
#[test]
fn test_refund_before_close_start_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[7u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let result = client.try_refund();
    assert!(result.is_err());
}

/// The recipient can close during the refund waiting period, and the close
/// automatically refunds the remainder to the funder.
#[test]
fn test_close_during_close_start() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[8u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    // Funder starts close.
    client.close_start();

    // Recipient closes during the waiting period.
    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig);
    assert_eq!(token.balance(&to), 300);

    // Close automatically refunded the remainder to the funder.
    assert_eq!(token.balance(&funder), 700);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Settle works during the close_start waiting period.
#[test]
fn test_settle_during_close_start() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[9u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    // Settle during the waiting period — does not close the channel.
    let sig = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig);
    assert_eq!(token.balance(&to), 200);
    assert_eq!(token.balance(&channel_id), 300);

    // Funder can still refund after the waiting period (gets remainder).
    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });

    client.refund();
    assert_eq!(token.balance(&funder), 800);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Settle works even after the channel is closed (after close_start effective
/// ledger reached), because settle does not check closed state.
#[test]
fn test_settle_after_close_start_effective() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[10u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });

    // Settle still works after the effective ledger.
    let sig = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig);
    assert_eq!(token.balance(&to), 200);
    assert_eq!(token.balance(&channel_id), 300);
}

/// Close fails if the commitment signature does not match.
#[test]
fn test_invalid_signature() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[11u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let wrong_key = SigningKey::from_bytes(&[12u8; 32]);

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 200).sign(&wrong_key);
    let result = client.try_close(&200, &sig);
    assert!(result.is_err());
}

/// Close works after the close_start effective ledger has been reached,
/// as long as there is still balance.
#[test]
fn test_close_after_close_start_effective() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[13u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });

    // Close still works after the effective ledger.
    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig);
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&funder), 700);
    assert_eq!(token.balance(&channel_id), 0);
}

/// The funder can top up the channel after creation.
#[test]
fn test_top_up_after_creation() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[14u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 300i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    assert_eq!(token.balance(&channel_id), 300);
    assert_eq!(token.balance(&funder), 700);

    client.top_up(&200);
    assert_eq!(token.balance(&channel_id), 500);
    assert_eq!(token.balance(&funder), 500);
}

/// Closing with a commitment for amount 0 refunds the full balance to the funder.
#[test]
fn test_close_zero_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[15u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 0).sign(&auth_key);
    client.close(&0, &sig);
    assert!(!has_event_type(&env, &channel_id, "withdraw"));
    assert_eq!(token.balance(&to), 0);
    assert_eq!(token.balance(&funder), 1000);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Closing for the full balance transfers everything to the recipient and
/// does not emit a spurious Refund event.
#[test]
fn test_close_full_balance_no_refund_event() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[23u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 500).sign(&auth_key);
    client.close(&500, &sig);
    assert!(!has_event_type(&env, &channel_id, "refund"));
    assert_eq!(token.balance(&to), 500);
    assert_eq!(token.balance(&funder), 500);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Calling close_start again resets the waiting period.
#[test]
fn test_close_start_resets_waiting_period() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[17u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += 50;
    });

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += 60;
    });

    let result = client.try_refund();
    assert!(result.is_err());

    env.ledger().with_mut(|li| {
        li.sequence_number += 50;
    });

    client.refund();
}

/// Calling refund twice succeeds but the second transfers nothing.
#[test]
fn test_refund_twice() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[18u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });

    client.refund();
    assert_eq!(token.balance(&funder), 1000);

    client.refund();
    assert!(!has_event_type(&env, &channel_id, "refund"));
    assert_eq!(token.balance(&funder), 1000);
}

/// Top up with amount 0 still requires the funder's auth.
#[test]
fn test_top_up_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[19u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    client.top_up(&0);
    assert_eq!(
        env.auths(),
        [(
            funder.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((channel_id.clone(), Symbol::new(&env, "top_up"), (0i128,).into_val(&env))),
                sub_invocations: [].into(),
            }
        )]
    );
    assert_eq!(client.balance(), 500);
}

/// Opening a channel with amount 0 still requires the funder's auth.
#[test]
fn test_open_zero_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[27u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 0i128, 100u32));
    assert_eq!(
        env.auths(),
        [(
            funder.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    channel_id.clone(),
                    Symbol::new(&env, "__constructor"),
                    (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 0i128, 100u32).into_val(&env),
                )),
                sub_invocations: [].into(),
            }
        )]
    );
    assert_eq!(token.balance(&channel_id), 0);
    assert_eq!(token.balance(&funder), 1000);
}

/// Refund succeeds at exactly the effective_at_ledger.
#[test]
fn test_refund_at_exact_effective_ledger() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[20u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period;
    });

    client.refund();
    assert_eq!(token.balance(&funder), 1000);
    assert_eq!(token.balance(&channel_id), 0);
}

/// close_start fails after the close effective ledger has been reached.
#[test]
fn test_close_start_fails_after_effective() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[21u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();

    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });

    let result = client.try_close_start();
    assert!(result.is_err());
}

/// close_start fails after close has been called.
#[test]
fn test_close_start_fails_after_close() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[22u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig);

    let result = client.try_close_start();
    assert!(result.is_err());
}

/// After close, refund succeeds immediately.
#[test]
fn test_refund_after_close() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[24u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig);

    client.refund();
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&funder), 700);
}

/// After close auto-refunds the funder the channel is final: top_up is
/// rejected (ROZOSCA-9) and a further close is rejected (ROZOSCA-2).
#[test]
fn test_close_twice() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[25u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &2000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    // First close: transfers 300, auto-refunds 200.
    let sig1 = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig1);
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&funder), 1700);

    // The channel cannot be reused: top up is rejected once closed.
    assert_eq!(client.try_top_up(&500), Err(Ok(Error::AlreadyClosed.into())));

    // And it is final: a second close is rejected, even with the same commitment.
    assert_eq!(client.try_close(&300, &sig1), Err(Ok(Error::Refunded.into())));
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&funder), 1700);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Once close_start has been called the funder cannot top up: a closing
/// channel cannot be reused without a challenge window (ROZOSCA-9).
#[test]
fn test_top_up_after_close_start_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[29u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    client.close_start();
    assert_eq!(client.try_top_up(&100), Err(Ok(Error::AlreadyClosed.into())));
    assert_eq!(token.balance(&channel_id), 500);
}

/// After refund the channel is final: tokens that later land in the channel
/// cannot be claimed by the recipient with an old commitment; only the
/// funder can reclaim them with another refund (ROZOSCA-2).
#[test]
fn test_settle_after_refund_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[30u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    // Recipient holds a commitment for 400 but never settles.
    let sig = Commitment::new(channel_id.clone(), 400).sign(&auth_key);

    client.close_start();
    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });
    client.refund();
    assert_eq!(token.balance(&funder), 1000);

    // Funder accidentally sends tokens straight to the channel afterwards.
    token.transfer(&funder, &channel_id, &300);
    assert_eq!(token.balance(&channel_id), 300);

    // The old commitment is worthless now.
    assert_eq!(client.try_settle(&400, &sig), Err(Ok(Error::Refunded.into())));
    assert_eq!(client.try_close(&400, &sig), Err(Ok(Error::Refunded.into())));
    assert_eq!(token.balance(&to), 0);

    // The funder reclaims the stray tokens.
    client.refund();
    assert_eq!(token.balance(&funder), 1000);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Close with a commitment amount exceeding the total deposited fails:
/// a commitment is only valid up to what is on chain (ROZOSCA-7).
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_close_amount_exceeds_deposit_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[26u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 600).sign(&auth_key);
    client.close(&600, &sig);
}

/// Settle with a commitment amount exceeding the total deposited fails and
/// transfers nothing; after a top up that covers it, the same commitment
/// settles in full (ROZOSCA-7).
#[test]
fn test_settle_exceeds_deposit_fails_until_top_up() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[28u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    // Commitment for more than the total deposited: rejected, nothing paid.
    let sig = Commitment::new(channel_id.clone(), 600).sign(&auth_key);
    let res = client.try_settle(&600, &sig);
    assert_eq!(res, Err(Ok(Error::InsufficientDeposit.into())));
    assert_eq!(token.balance(&to), 0);
    assert_eq!(token.balance(&channel_id), 500);
    assert_eq!(client.withdrawn(), 0);

    // After a top up that covers it, the same commitment settles in full.
    client.top_up(&300);
    client.settle(&600, &sig);
    assert_eq!(token.balance(&to), 600);
    assert_eq!(token.balance(&channel_id), 200);
    assert_eq!(client.withdrawn(), 600);
}

/// Top up emits a Deposit event, and the constructor's initial deposit does too.
#[test]
fn test_top_up_emits_deposit_event() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[29u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    client.top_up(&200);
    assert!(has_event_type(&env, &channel_id, "deposit"));
}

/// Tokens sent straight to the channel address are not deposits: they do not
/// raise `deposited`, so they cannot enlarge what a commitment can claim
/// after close_start, and only the funder gets them back (ROZOSCA-9).
#[test]
fn test_direct_transfer_does_not_raise_deposited() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[31u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &2000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);
    assert_eq!(client.deposited(), 500);

    client.close_start();

    // Funder bypasses the blocked top_up with a direct transfer.
    token.transfer(&funder, &channel_id, &1000);
    assert_eq!(token.balance(&channel_id), 1500);
    assert_eq!(client.deposited(), 500);

    // A commitment for the enlarged balance is rejected.
    let sig = Commitment::new(channel_id.clone(), 1200).sign(&auth_key);
    assert_eq!(client.try_settle(&1200, &sig), Err(Ok(Error::InsufficientDeposit.into())));

    // A commitment within the real deposit still settles.
    let sig = Commitment::new(channel_id.clone(), 400).sign(&auth_key);
    client.settle(&400, &sig);
    assert_eq!(token.balance(&to), 400);

    // The funder reclaims everything else after the waiting period.
    env.ledger().with_mut(|li| {
        li.sequence_number += refund_waiting_period + 1;
    });
    client.refund();
    assert_eq!(token.balance(&funder), 1600);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Settling exactly the deposited total after a partial withdrawal is the
/// boundary of the InsufficientDeposit check.
#[test]
fn test_settle_exactly_deposited_after_partial() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[32u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    let sig = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig);
    client.top_up(&300);
    assert_eq!(client.deposited(), 800);

    let sig = Commitment::new(channel_id.clone(), 800).sign(&auth_key);
    client.settle(&800, &sig);
    assert_eq!(token.balance(&to), 800);
    assert_eq!(token.balance(&channel_id), 0);
    assert_eq!(client.withdrawn(), 800);

    let sig = Commitment::new(channel_id.clone(), 801).sign(&auth_key);
    assert_eq!(client.try_settle(&801, &sig), Err(Ok(Error::InsufficientDeposit.into())));
}

/// If the automatic refund in `close` fails, the channel is still final for
/// the recipient, and the funder recovers the balance with `refund` later.
#[test]
fn test_close_auto_refund_fails_then_refund() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[33u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    // A token whose issuer can revoke authorization, so a transfer to the
    // funder can be made to fail.
    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    sac.issuer().set_flag(IssuerFlags::RevocableFlag);
    let token_addr = sac.address();
    let token = TokenClient::new(&env, &token_addr);
    let asset_admin = StellarAssetClient::new(&env, &token_addr);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);

    // The funder can no longer receive the token, so the auto refund fails.
    asset_admin.set_authorized(&funder, &false);

    let sig = Commitment::new(channel_id.clone(), 300).sign(&auth_key);
    client.close(&300, &sig);
    assert_eq!(token.balance(&to), 300);
    assert_eq!(token.balance(&channel_id), 200);
    assert_eq!(token.balance(&funder), 500);
    assert!(!has_event_type(&env, &channel_id, "refund"));

    // Final for the recipient regardless.
    let sig2 = Commitment::new(channel_id.clone(), 400).sign(&auth_key);
    assert_eq!(client.try_settle(&400, &sig2), Err(Ok(Error::Refunded.into())));
    assert_eq!(client.try_close(&400, &sig2), Err(Ok(Error::Refunded.into())));

    // Once the funder can receive again, refund recovers the balance.
    asset_admin.set_authorized(&funder, &true);
    client.refund();
    assert_eq!(token.balance(&funder), 700);
    assert_eq!(token.balance(&channel_id), 0);
}

/// Public getters expose the commitment key and the close deadline (H-02).
#[test]
fn test_getters_commitment_key_and_close_deadline() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[34u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);
    let refund_waiting_period: u32 = 100;

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, refund_waiting_period));
    let client = ContractClient::new(&env, &channel_id);

    assert_eq!(client.commitment_key(), auth_pubkey);
    assert_eq!(client.close_effective_at_ledger(), None);

    client.close_start();
    let expected = env.ledger().sequence() + refund_waiting_period;
    assert_eq!(client.close_effective_at_ledger(), Some(expected));

    // A recipient close makes the deadline the current ledger.
    let sig = Commitment::new(channel_id.clone(), 100).sign(&auth_key);
    client.close(&100, &sig);
    assert_eq!(client.close_effective_at_ledger(), Some(env.ledger().sequence()));
}

/// A refund waiting period above the supported maximum is rejected (I-7).
#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn test_refund_waiting_period_too_long() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[35u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 0i128, MAX_REFUND_WAITING_PERIOD + 1));
}

/// Recipient and funder addresses are event topics (H-04 / I-9).
#[test]
fn test_party_addresses_are_event_topics() {
    let env = Env::default();
    env.mock_all_auths();

    let auth_key = SigningKey::from_bytes(&[36u8; 32]);
    let auth_pubkey = BytesN::from_array(&env, &auth_key.verifying_key().to_bytes());

    let to = Address::generate(&env);
    let funder = Address::generate(&env);

    let (token_addr, _token, asset_admin) = create_token(&env);
    asset_admin.mint(&funder, &1000);

    let channel_id = env.register(Contract, (token_addr.clone(), funder.clone(), auth_pubkey.clone(), to.clone(), 500i128, 100u32));
    let client = ContractClient::new(&env, &channel_id);
    let to_val: xdr::ScVal = to.clone().try_into().unwrap();
    let from_val: xdr::ScVal = funder.clone().try_into().unwrap();

    // The test event buffer only holds the last invocation, so check each
    // event right after the call that emits it.
    let has_topic = |name: &str, val: &xdr::ScVal| {
        let events = env.events().all().filter_by_contract(&channel_id);
        events.events().iter().any(|e| match &e.body {
            xdr::ContractEventBody::V0(body) => body.topics.first() == Some(&xdr::ScVal::Symbol(xdr::ScSymbol(name.try_into().unwrap()))) && body.topics.iter().any(|t| t == val),
        })
    };

    let sig = Commitment::new(channel_id.clone(), 200).sign(&auth_key);
    client.settle(&200, &sig);
    assert!(has_topic("withdraw", &to_val));

    client.top_up(&100);
    assert!(has_topic("deposit", &from_val));
}
