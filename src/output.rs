// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::raw;
use bitcoin::taproot::{TapLeafHash, TapTree};
use bitcoin::{secp256k1, Amount, ScriptBuf};

use crate::prelude::BTreeMap;

/// A PSBT output guaranteed to be valid for PSBT version 2.
///
/// This is an exact copy of `bitcoin::psbt::Output` but with the required PSBT fields non-optional.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    /// The output's amount.
    pub amount: Amount,

    /// The script for this output, also known as the scriptPubKey.
    pub script_pubkey: ScriptBuf,

    /// The redeem script for this output, if one exists.
    pub redeem_script: Option<ScriptBuf>,

    /// The witness script for this output, if one exists.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to spend this output to their corresponding master key
    /// fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The X-only pubkey used as the internal key in this output.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot output tree.
    pub tap_tree: Option<TapTree>,

    /// Map of Taproot x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
}

impl Output {
    pub(crate) fn from_v2(output: bitcoin::psbt::Output) -> Result<Output, V2InvalidError> {
        assert_is_valid_v2(&output)?;

        let amount = output.amount.unwrap();
        let script_pubkey = output.script_pubkey.unwrap();

        Ok(Output {
            redeem_script: output.redeem_script,
            witness_script: output.witness_script,
            bip32_derivation: output.bip32_derivation,
            amount,
            script_pubkey,
            tap_internal_key: output.tap_internal_key,
            tap_tree: output.tap_tree,
            tap_key_origins: output.tap_key_origins,
        })
    }

    pub(crate) fn from_v0(output: bitcoin::psbt::Output, txout: TxOut) -> Result<Output, V0InvalidError> {
        assert_is_valid_v0(&output)?;

        let amount = txout.amount.unwrap();
        let script_pubkey = txout.script_pubkey.unwrap();

        Ok(Output {
            redeem_script: output.redeem_script,
            witness_script: output.witness_script,
            bip32_derivation: output.bip32_derivation,
            amount,
            script_pubkey,
            tap_internal_key: output.tap_internal_key,
            tap_tree: output.tap_tree,
            tap_key_origins: output.tap_key_origins,
        })
    }
        
    // Converts this output to a `rust-bitcoin` one.
    pub(crate) fn to_v2(self) -> bitcoin::psbt::Output {
        bitcoin::psbt::Output {
            redeem_script: self.redeem_script,
            witness_script: self.witness_script,
            bip32_derivation: self.bip32_derivation,
            amount: Some(self.amount),
            script_pubkey: Some(self.script_pubkey),
            tap_internal_key: self.tap_internal_key,
            tap_tree: self.tap_tree,
            tap_key_origins: self.tap_key_origins,
            proprietary: BTeeMap::default(),
            unknown: BTeeMap::default(),
        }
    }

    // Converts this output to a `rust-bitcoin` one.
    pub(crate) fn to_v0(self) -> bitcoin::psbt::Output {
        let mut output = self.to_v2();
        output.amount = None;
        output.script_pubkey = None;
        output
    }

    /// Creates the [`TxOut`] associated with this `Output`.
    pub(crate) fn tx_out(&self) -> TxOut {
        TxOut { value: self.amount, script_pubkey: self.script_pubkey.clone() }
    }

    /// Combines this [`Output`] with `other` `Output` (as described by BIP-174).
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.amount != other.amount {
            return Err(CombineError::AmountMismatch { this: self.amount, that: other.amount });
        }

        if self.script_pubkey != other.script_pubkey {
            return Err(CombineError::ScriptPubkeyMismatch {
                this: self.script_pubkey.clone(),
                that: other.script_pubkey,
            });
        }

        v2_combine_option!(redeem_script, self, other);
        v2_combine_option!(witness_script, self, other);
        v2_combine_map!(bip32_derivations, self, other);
        v2_combine_option!(tap_internal_key, self, other);
        v2_combine_option!(tap_tree, self, other);
        v2_combine_map!(tap_key_origins, self, other);
        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

        Ok(())
    }
}

// TODO: Upstream.
pub(crate) fn assert_is_valid_v2(output: &bitcoin::psbt::Output) -> Result<(), V2InvalidError> {
    use V2InvalidError::*;

    if output.amount.is_none() {
        return Err(MissingAmount);
    }
    if output.script_pubkey.is_none() {
        return Err(MissingScriptPubkey);
    }

    Ok(())
}

/// Output is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2InvalidError {
    /// Field `amount` is not set (PSBT_OUT_AMOUNT).
    MissingAmount,
    /// Field `script_pubkey` is not set (PSBT_OUT_SCRIPT).
    MissingScriptPubkey,
}

impl fmt::Display for V2InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use V2InvalidError::*;

        match *self {
            MissingAmount =>
                write!(f, "invalid PSBT v2, missing previous amount (PSBT_OUT_AMOUNT)"),
            MissingScriptPubkey =>
                write!(f, "invalid PSBT v2, missing script pubkey (PSBT_OUT_SCRIPT)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V2InvalidError::*;

        match *self {
            MissingAmount | MissingScriptPubkey => None,
        }
    }
}

// TODO: Upstream.
pub(crate) fn assert_is_valid_v0(input: &bitcoin::psbt::Input) -> Result<(), V0InvalidError> {
    use V0InvalidError::*;

    if input.sequence.is_some() {
        return Err(HasAmount);
    }
    if input.script_pubkey.is_some() {
        return Err(HasScriptPubkey);
    }

    Ok(())
}

/// Output is not valid according to the Version 0 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0InvalidError {
    /// Field `amount` should be excluded for v0 (PSBT_OUT_AMOUNT).
    HasAmount,
    /// Field `script_pubkey` should be excluded for v0 (PSBT_OUT_SCRIPT).
    HasScriptPubkey,
}

impl fmt::Display for V0InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IsValidPsbtV2Error::*;

        match *self {
            HasAmount =>
                write!(f, "invalid v2 input, `amount` should be excluded (PSBT_OUT_AMOUNT)"),
            HasScriptPubkey =>
                write!(f, "invalid v2 input, `min_time` should be excluded (PSBT_OUT_SCRIPT)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V0InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V0InvalidError::*;

        match *self {
            HasAmount | HasScriptPubkey => None,
        }
    }
}
