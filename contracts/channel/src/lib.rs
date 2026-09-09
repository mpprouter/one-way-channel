//! # Channel
//!
//! A unidirectional payment channel contract for Soroban (Stellar).
//!
//! A payment channel allows a funder to make many small payments to a recipient
//! off-chain, with only two on-chain transactions: opening the channel and
//! closing it. This avoids per-payment transaction fees and latency.
//!
//! > [!WARNING]
//! > **The contracts in this repository have not been audited.**
//!
//! ## Participants
//!
//! - **Funder (`from`)**: Deposits tokens into the channel and signs
//!   commitments authorizing the recipient to settle or close the channel
//!   and receive a given amount.
//! - **Recipient (`to`)**: Receives commitments off-chain and can settle or
//!   close the channel on-chain at any time using a signed commitment.
//!
//! ## Expectations
//!
//! Participants have the following responsibilities to receive the funds owing
//! to them.
//!
//! ### Funder
//!
//! - Keeping the private key corresponding to `commitment_key` (the commitment signing key) secret.
//!
//! ### Recipient
//!
//! - Verifies the `refund_waiting_period` at channel creation is long
//!   enough to allow them to react to a close_start event.
//! - Verifies, against the chain, that the channel was deployed by the
//!   expected factory with the expected token, `to`, and `commitment_key`,
//!   and that no close has started, before accepting any commitment.
//! - Verifies the `amount` in each commitment does not exceed the channel's
//!   `deposited` total, and that `balance` still covers `amount - withdrawn`.
//!   The contract rejects commitments beyond `deposited`, and a transfer
//!   that the balance cannot cover fails, so such a commitment is worthless.
//! - Keeps the commitment with the highest `amount`. Older commitments stay
//!   valid signatures but are useless: settlement pays the cumulative
//!   `amount` minus what was already withdrawn.
//! - Monitors the channel for [`event::Close`] events.
//! - Calls `settle` with a commitment promptly after seeing a close_start
//!   event, before the funder calls `refund`.
//!
//! ## State diagram
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Open: __constructor
//!     Open --> Refunded: close
//!     Open --> Closing: close_start
//!     Closing --> Refunded: close
//!     Closing --> Closed: [after wait]
//!     Closed --> Refunded: refund
//!     Refunded --> [*]
//! ```
//!
//! `settle` can be called in any state before Refunded. `close` can be
//! called while Open, Closing, or Closed. `top_up` can only be called while
//! Open. `refund` can be called in Closed and Refunded.
//!
//! ## Functions
//!
//! ### Lifecycle
//!
//! | Function | Description |
//! |---|---|
//! | `__constructor` | Open a channel with an initial deposit. Callable by the deployer, authorized by the funder. |
//! | `top_up` | Deposit additional tokens into the channel. |
//! | `extend` | Extend the lifetime (TTL) of the channel's storage. |
//! | `settle` | Withdraw funds using a signed commitment without closing the channel. |
//! | `close` | Close the channel using a signed commitment, withdrawing funds to the recipient. Automatically attempts to refund the funder. |
//! | `close_start` | Begin closing the channel, effective after a waiting period. |
//! | `refund` | Refund the remaining balance to the funder after the close is effective. |
//!
//! ### Helpers
//!
//! | Function | Description |
//! |---|---|
//! | `prepare_commitment` | Generate the commitment bytes to sign. |
//!
//! ### Getters (static)
//!
//! | Function | Description |
//! |---|---|
//! | `token` | Returns the token address. |
//! | `from` | Returns the funder address. |
//! | `to` | Returns the recipient address. |
//! | `refund_waiting_period` | Returns the refund waiting period in ledgers. |
//!
//! ### Getters (dynamic)
//!
//! | Function | Description |
//! |---|---|
//! | `deposited` | Returns the total amount deposited. |
//! | `balance` | Returns the current balance. |
//! | `withdrawn` | Returns the total amount already withdrawn. |
//!
//! ## Lifecycle
//!
//! ### 1. Open
//!
//! The channel is deployed with a SEP-41 token, funder address, recipient
//! address, an ed25519 `commitment_key` (public key), an initial deposit
//! amount, and a `refund_waiting_period` (in ledgers).
//!
//! The funder's tokens are transferred into the channel contract on deployment.
//! The funder can also top up the channel later using [`Contract::top_up`].
//! Only these two paths count towards `deposited`, the ceiling for
//! commitments; tokens sent directly to the channel address are not deposits
//! and can only be reclaimed by the funder via `refund`.
//!
//! ### 2. Off-chain payments
//!
//! The funder makes payments by signing commitments off-chain and sending them
//! to the recipient. A commitment authorizes the recipient to settle or
//! close the channel and receive a **cumulative total** amount. A newer
//! commitment supersedes an older one only in the sense that its amount is
//! higher; the older signature remains valid but pays nothing extra.
//!
//! For example:
//! - Commitment for 100: recipient can settle or close and receive 100.
//! - Commitment for 140: recipient can settle or close and receive 140
//!   (40 more if 100 was already settled).
//!
//! A commitment is an XDR serialized [`Commitment`] struct containing a domain
//! separator (`chancmmt`), the network ID, the channel contract address, and
//! the amount. The
//! funder signs the serialized bytes with the ed25519 key corresponding to the
//! `commitment_key`. Use [`Contract::prepare_commitment`] as a convenience to
//! generate the bytes to sign.
//!
//! The serialized commitment is an XDR `ScVal::Map` with four entries
//! (sorted alphabetically by key):
//!
//! ```text
//! ScVal::Map({
//!     Symbol("amount"):  I128(amount),
//!     Symbol("channel"): Address(channel_contract_address),
//!     Symbol("domain"):  Symbol("chancmmt"),
//!     Symbol("network"): BytesN<32>(network_id),
//! })
//! ```
//!
//! ### 3. Settle
//!
//! The recipient calls [`Contract::settle`] at any time with a commitment
//! amount and its signature. The contract verifies the signature, then
//! transfers the difference between the commitment amount and what has
//! already been withdrawn. If the commitment amount is less than or equal
//! to what has already been withdrawn, no transfer occurs.
//!
//! A commitment whose amount exceeds the channel's `deposited` total is
//! rejected outright. Nothing is transferred and nothing stays claimable:
//! the recipient must never accept a commitment beyond `deposited`.
//!
//! Settlement is all-or-nothing: if the channel's token balance ever drops
//! below what a commitment needs (for example through an issuer clawback on
//! a token with `AUTH_CLAWBACK_ENABLED`, or a fee-on-transfer token), that
//! commitment can no longer be settled. The recipient should therefore only
//! accept channels denominated in a token whose issuer it trusts and whose
//! transfers move the exact amount.
//!
//! Settlement is optional. The recipient does not need to settle at all —
//! [`Contract::close`] will also settle any unsettled amount. The recipient
//! may choose to settle periodically to receive funds without closing the
//! channel.
//!
//! ### 4. Close
//!
//! The recipient calls [`Contract::close`] with a commitment amount and its
//! signature. Like `settle`, only the difference between the commitment
//! amount and what has already been withdrawn is transferred.
//!
//! After transferring the committed funds, the close function automatically
//! attempts to refund the remaining balance to the funder. This refund attempt
//! uses `try_transfer` and will silently succeed or fail without affecting the
//! withdrawal. If the automatic refund fails, the funder can call
//! [`Contract::refund`] to reclaim the remaining balance.
//!
//! Can be called while the channel is open or closing, but only once:
//! `close` makes the channel final, so a second `close` or a later `settle`
//! is rejected. If the automatic refund failed, the funder recovers the
//! balance with [`Contract::refund`].
//!
//! ### 5. Close Start
//!
//! The funder calls [`Contract::close_start`] to begin closing the channel.
//! The close does not take effect immediately — there is a waiting period of
//! `refund_waiting_period` ledgers.
//!
//! The recipient can still call [`Contract::settle`] or [`Contract::close`]
//! during and after the waiting period. Once the waiting period has elapsed,
//! the funder can call `refund` to reclaim the remaining balance.
//!
//! **Important:** The recipient should monitor for [`event::Close`] events and
//! settle or close before the funder calls `refund`.
//!
//! ### 6. Refund
//!
//! After the refund waiting period has elapsed, the funder calls
//! [`Contract::refund`] to reclaim whatever balance remains in the channel.
//! This transfers the **entire** remaining token balance to the funder,
//! including any amount the recipient was entitled to but did not settle or
//! close for.
//! The contract does not reserve funds for the recipient. If the recipient
//! has not closed before the funder calls refund, those funds are lost to
//! the recipient and assumed to be of no interest to the recipient.
//!
//! Refund makes the channel final. The recipient can no longer settle or
//! close, and the funder can no longer top up, so tokens that arrive
//! afterwards belong to the funder alone and are reclaimed with a further
//! `refund`. A closing channel likewise cannot be topped up, and tokens sent
//! directly to the address never raise `deposited`, so a channel is never
//! reused after a close has started.
//!
//! ## Storage lifetime
//!
//! All channel state is stored in instance storage. State-changing functions
//! (`top_up`, `settle`, `close`, `close_start`) extend the storage TTL as a
//! side effect, and anyone can call [`Contract::extend`] to extend it
//! explicitly. A channel left idle for a long period can still have its
//! storage archived; it must then be restored before use.
//!
//! ## Security
//!
//! - Commitments are signed with an ed25519 key, not a Stellar account. The
//!   `commitment_key` is set at deployment and cannot be changed.
//! - The commitment includes a domain separator, the network ID, and the
//!   channel contract address, preventing signatures from being reused across
//!   networks, channels, or confused with other signed payloads.
//! - The refund waiting period protects the recipient: it gives them time to
//!   settle or close using their latest commitment before the funder can
//!   reclaim funds.

#![no_std]
#[allow(unused_imports)]
use soroban_sdk::{assert_with_error, contract, contracterror, contractimpl, contracttype, symbol_short, token, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol};

pub mod event;

/// Approximate number of ledgers per day, assuming 5 second ledger close times.
const LEDGERS_PER_DAY: u32 = 17280;
/// When the instance storage TTL drops below this threshold, extend it.
const TTL_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
/// The TTL to extend the instance storage to.
const TTL_EXTEND_TO: u32 = 60 * LEDGERS_PER_DAY;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NegativeAmount = 1,
    NotClosed = 2,
    RefundWaitingPeriodNotElapsed = 3,
    AlreadyClosed = 4,
    InsufficientDeposit = 5,
    Refunded = 6,
    Overflow = 7,
}

#[contracttype]
pub enum DataKey {
    Token,
    From,
    CommitmentKey,
    To,
    RefundWaitingPeriod,
    WithdrawnAmount,
    CloseEffectiveAtLedger,
    Refunded,
    DepositedAmount,
}

#[contracttype]
pub struct Commitment {
    domain: Symbol,
    network: BytesN<32>,
    channel: Address,
    amount: i128,
}

impl Commitment {
    pub fn new(channel: Address, amount: i128) -> Self {
        let network = channel.env().ledger().network_id();
        Commitment {
            domain: symbol_short!("chancmmt"),
            network,
            channel,
            amount,
        }
    }

    fn into_bytes(&self) -> Bytes {
        let env = self.channel.env();
        self.to_xdr(env)
    }

    fn verify(self, sig: &BytesN<64>) {
        let env = self.channel.env().clone();
        let commitment_key: BytesN<32> = env.storage().instance().get(&DataKey::CommitmentKey).unwrap();
        let payload = self.into_bytes();
        env.crypto().ed25519_verify(&commitment_key, &payload, sig);
    }
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    /// Open a channel by depositing tokens from the funder to the contract.
    ///
    /// - `token`: The SEP-41 token used for payments.
    /// - `from`: The funder who deposits tokens into the channel.
    /// - `commitment_key`: The ed25519 public key used to verify commitment
    ///   signatures. See `prepare_commitment` for details on
    ///   commitments.
    /// - `to`: The recipient who can settle or close the channel using
    ///   signed commitments.
    /// - `amount`: The initial deposit amount.
    /// - `refund_waiting_period`: The number of ledgers the recipient has to
    ///   close after `close_start` is called, before `refund`
    ///   becomes available. This value should be large enough to give the
    ///   recipient time to observe a close event and submit a close,
    ///   otherwise the recipient may not accept the channel. However, it
    ///   should not be so large that the funder cannot reclaim funds in a
    ///   timely manner. Setting zero or a very low number results in
    ///   near-immediate refunds, which is almost certainly not useful for
    ///   either participant.
    ///
    /// Callable by the deployer.
    ///
    /// # Auth
    /// - `from`: required.
    pub fn __constructor(env: &Env, token: Address, from: Address, commitment_key: BytesN<32>, to: Address, amount: i128, refund_waiting_period: u32) {
        assert_with_error!(env, amount >= 0, Error::NegativeAmount);

        // Store channel configuration.
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::From, &from);
        env.storage().instance().set(&DataKey::CommitmentKey, &commitment_key);
        env.storage().instance().set(&DataKey::To, &to);
        env.storage().instance().set(&DataKey::RefundWaitingPeriod, &refund_waiting_period);

        // Deposit initial funds.
        Self::top_up(env, amount);

        env.events().publish_event(&event::Open {
            from,
            commitment_key,
            to,
            token,
            amount,
            refund_waiting_period,
        });
    }

    /// Top up the channel by transferring the amount of the channels token from the funder (from
    /// address).
    ///
    /// Only deposits made through this function (and the constructor) count
    /// towards `deposited`, the ceiling for commitments. Tokens transferred
    /// directly to the channel address are not deposits: the recipient can
    /// never claim them and the funder reclaims them via `refund`.
    ///
    /// Fails once `close` or `close_start` has been called: a closing or
    /// closed channel cannot be reused, because the recipient would have no
    /// challenge window against a refund.
    ///
    /// Callable by funder (from).
    ///
    /// # Auth
    /// - `from`: required.
    pub fn top_up(env: &Env, amount: i128) {
        assert_with_error!(env, amount >= 0, Error::NegativeAmount);
        assert_with_error!(env, Self::close_effective_at_ledger(env).is_none(), Error::AlreadyClosed);
        let from = Self::from(env);
        from.require_auth();
        Self::extend_instance_ttl(env);
        if amount > 0 {
            // Record the deposit, then transfer tokens from the funder to the channel.
            let deposited = Self::deposited(env).checked_add(amount);
            assert_with_error!(env, deposited.is_some(), Error::Overflow);
            env.storage().instance().set(&DataKey::DepositedAmount, &deposited.unwrap());
            Self::token_client(env).transfer(&from, &env.current_contract_address(), &amount);
            env.events().publish_event(&event::Deposit { from, amount });
        }
    }

    /// Extend the lifetime (TTL) of the channel's instance storage, so that
    /// a long-lived channel is not archived while in use. Extension also
    /// happens as a side effect of `top_up`, `settle`, `close`, and
    /// `close_start`.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn extend(env: &Env) {
        Self::extend_instance_ttl(env);
    }

    /// Returns the token address.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn token(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Token).unwrap()
    }

    /// Returns the funder address.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn from(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::From).unwrap()
    }

    /// Returns the recipient address.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn to(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::To).unwrap()
    }

    /// Returns the refund waiting period in ledgers.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn refund_waiting_period(env: &Env) -> u32 {
        env.storage().instance().get(&DataKey::RefundWaitingPeriod).unwrap()
    }

    /// Returns the token balance held by the channel contract.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn balance(env: &Env) -> i128 {
        Self::token_client(env).balance(&env.current_contract_address())
    }

    /// Returns the total amount deposited into the channel through the
    /// constructor and `top_up`. This is the ceiling for commitments.
    ///
    /// Tokens transferred directly to the channel address do not count: they
    /// cannot be claimed by the recipient and are only reclaimable by the
    /// funder via `refund`.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn deposited(env: &Env) -> i128 {
        env.storage().instance().get(&DataKey::DepositedAmount).unwrap_or(0)
    }

    /// Returns the total amount already withdrawn by the recipient via
    /// `settle` or `close`.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn withdrawn(env: &Env) -> i128 {
        env.storage().instance().get(&DataKey::WithdrawnAmount).unwrap_or(0)
    }

    /// Returns the XDR serialized bytes of a commitment for the given amount.
    ///
    /// The returned bytes must be signed by the ed25519 key corresponding to
    /// the `commitment_key` stored in the channel. The resulting signature,
    /// along with the amount, can be passed to `settle` or `close` by the
    /// recipient.
    ///
    /// Commitments are typically prepared off-chain. This function is provided
    /// as a convenience.
    ///
    /// Callable by anyone.
    ///
    /// # Auth
    /// None.
    pub fn prepare_commitment(env: &Env, amount: i128) -> Bytes {
        assert_with_error!(&env, amount >= 0, Error::NegativeAmount);
        Commitment::new(env.current_contract_address(), amount).into_bytes()
    }

    /// Settle funds to the recipient using a signed commitment without closing
    /// the channel. The amount is the cumulative total the recipient is
    /// entitled to. Only the difference between the amount and what has already
    /// been withdrawn is transferred.
    ///
    /// The recipient does not need to settle after every commitment. They can
    /// accumulate multiple commitments and settle using only the latest
    /// (highest amount) commitment.
    ///
    /// If an older commitment with a lower amount is used after a higher amount
    /// has already been withdrawn, no funds are transferred.
    ///
    /// Fails if the amount exceeds the total deposited into the channel
    /// (`deposited`): a commitment is only valid up to what is on chain.
    ///
    /// Can be called after `close_start`, up until the funder calls
    /// [`Contract::refund`]; after a refund or a `close` the channel is final
    /// and settle fails.
    ///
    /// Callable by the recipient (to).
    ///
    /// # Auth
    /// - `to`: required.
    /// - Commitment signature serves as commitment_key authorization.
    pub fn settle(env: &Env, amount: i128, sig: BytesN<64>) {
        assert_with_error!(&env, amount >= 0, Error::NegativeAmount);
        assert_with_error!(env, !Self::refunded(env), Error::Refunded);

        // Verify the recipient and commitment signature.
        let to = Self::to(env);
        to.require_auth();
        Commitment::new(env.current_contract_address(), amount).verify(&sig);
        Self::extend_instance_ttl(env);

        // Transfer only the difference from what has already been withdrawn.
        Self::withdraw(env, to, amount);
    }

    /// Close the channel using a signed commitment, withdrawing funds to the
    /// recipient. The amount is the cumulative total the recipient is entitled
    /// to. Only the difference between the amount and what has already been
    /// withdrawn is transferred. Fails if the amount exceeds the total
    /// deposited into the channel (`deposited`).
    ///
    /// After transferring, this function automatically attempts to refund the
    /// remaining balance to the funder using `try_transfer`. This refund
    /// attempt will silently succeed or fail without affecting the withdrawal.
    /// If the automatic refund fails, the funder can call [`Contract::refund`]
    /// to reclaim the remaining balance. Either way the channel is final after
    /// `close`, exactly as after [`Contract::refund`].
    ///
    /// Can be called while the channel is open or closing, but only once:
    /// after `close` or `refund` the channel is final and close fails.
    ///
    /// Callable by the recipient (to).
    ///
    /// # Auth
    /// - `to`: required.
    /// - Commitment signature serves as commitment_key authorization.
    pub fn close(env: &Env, amount: i128, sig: BytesN<64>) {
        assert_with_error!(&env, amount >= 0, Error::NegativeAmount);
        assert_with_error!(env, !Self::refunded(env), Error::Refunded);

        // Verify the recipient and commitment signature.
        let to = Self::to(env);
        to.require_auth();
        Commitment::new(env.current_contract_address(), amount).verify(&sig);
        Self::extend_instance_ttl(env);

        // Transfer only the difference from what has already been withdrawn.
        Self::withdraw(env, to, amount);

        // Mark the channel as closed immediately if not already closed, or
        // resolve a pending close_start by setting the effective ledger to now.
        // If already effective, don't change it, the channel is already
        // effectively closed, and this close is just withdrawaing and
        // refunding.
        let effective_at_ledger = env.ledger().sequence();
        let already_effective = Self::close_effective_at_ledger(env).is_some_and(|l| l <= effective_at_ledger);
        if !already_effective {
            env.storage().instance().set(&DataKey::CloseEffectiveAtLedger, &effective_at_ledger);
            env.events().publish_event(&event::Close { effective_at_ledger });
        }

        // Attempt to refund the remaining balance to the funder.
        let from = Self::from(env);
        let tc = Self::token_client(env);
        let balance = tc.balance(&env.current_contract_address());
        // The channel is final from here on. If the automatic refund fails
        // the funder recovers the balance with `refund`.
        env.storage().instance().set(&DataKey::Refunded, &true);
        if balance > 0 {
            if tc.try_transfer(&env.current_contract_address(), &from, &balance).is_ok() {
                env.events().publish_event(&event::Refund { from, amount: balance });
            }
        }
    }

    /// Begin closing the channel, effective after a waiting period. The
    /// recipient can still settle or close during and after the waiting
    /// period. After the close is effective, the funder can call refund to
    /// reclaim the remaining balance.
    ///
    /// **Important:** The recipient should settle or close whenever they see
    /// a [`event::Close`], before the funder calls `refund`.
    ///
    /// Callable by the funder (from).
    ///
    /// # Auth
    /// - `from`: required.
    pub fn close_start(env: &Env) -> Result<(), Error> {
        // Reject if the close effective ledger has already been reached.
        if let Some(effective_at_ledger) = Self::close_effective_at_ledger(env) {
            if env.ledger().sequence() >= effective_at_ledger {
                return Err(Error::AlreadyClosed);
            }
        }

        // Verify the funder.
        let from = Self::from(env);
        from.require_auth();
        Self::extend_instance_ttl(env);

        // Set the close effective ledger.
        let refund_waiting_period = Self::refund_waiting_period(env);
        let effective_at_ledger = env.ledger().sequence().saturating_add(refund_waiting_period);
        env.storage().instance().set(&DataKey::CloseEffectiveAtLedger, &effective_at_ledger);

        env.events().publish_event(&event::Close { effective_at_ledger });
        Ok(())
    }

    /// Refund the remaining balance to the funder after the close is effective.
    ///
    /// Makes the channel final: the recipient can no longer settle or close,
    /// so any tokens that arrive afterwards belong to the funder alone.
    ///
    /// Can be called multiple times. This is useful if the funder accidentally
    /// transfers additional tokens to the channel after closing — they can
    /// call refund again to reclaim the additional balance.
    ///
    /// Callable by the funder (from), after the close effective_at_ledger has
    /// been reached.
    ///
    /// # Auth
    /// - `from`: required.
    pub fn refund(env: &Env) -> Result<(), Error> {
        // Verify the close is effective.
        let effective_at_ledger = Self::close_effective_at_ledger(env).ok_or(Error::NotClosed)?;
        if env.ledger().sequence() < effective_at_ledger {
            return Err(Error::RefundWaitingPeriodNotElapsed);
        }

        // Verify the funder.
        let from = Self::from(env);
        from.require_auth();

        // The channel is final from here on, whether or not there is a
        // balance to transfer.
        env.storage().instance().set(&DataKey::Refunded, &true);

        // Transfer the remaining balance to the funder.
        let tc = Self::token_client(env);
        let balance = tc.balance(&env.current_contract_address());
        if balance > 0 {
            tc.transfer(&env.current_contract_address(), &from, &balance);
            env.events().publish_event(&event::Refund { from, amount: balance });
        }
        Ok(())
    }
}

impl Contract {
    fn token_client(env: &Env) -> token::Client<'_> {
        token::Client::new(env, &Self::token(env))
    }

    fn extend_instance_ttl(env: &Env) {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Transfer to the recipient the difference between the cumulative
    /// committed amount and what has already been withdrawn. Fails if the
    /// committed amount exceeds the total deposited, so a commitment that
    /// settles is always one that was fully backed on chain.
    fn withdraw(env: &Env, to: Address, amount: i128) {
        assert_with_error!(env, amount <= Self::deposited(env), Error::InsufficientDeposit);
        let payout = amount - Self::withdrawn(env);
        if payout > 0 {
            env.storage().instance().set(&DataKey::WithdrawnAmount, &amount);
            Self::token_client(env).transfer(&env.current_contract_address(), &to, &payout);
            env.events().publish_event(&event::Withdraw { to, amount: payout });
        }
    }

    fn close_effective_at_ledger(env: &Env) -> Option<u32> {
        env.storage().instance().get(&DataKey::CloseEffectiveAtLedger)
    }

    fn refunded(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::Refunded).unwrap_or(false)
    }
}

mod test;
