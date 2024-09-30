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
    /// The redeem script for this output.
    ///
    /// PSBT_OUT_REDEEM_SCRIPT: Optional for v0, optional for v2.
    pub redeem_script: Option<ScriptBuf>,

    /// The witness script for this output.
    ///
    /// PSBT_OUT_WITNESS_SCRIPT: Optional for v0, optional for v2.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to spend this output to their corresponding master key
    /// fingerprints and derivation paths.
    ///
    /// PSBT_OUT_BIP32_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The output's amount (serialized as satoshis).
    ///
    /// PSBT_OUT_AMOUNT: Excluded for v0, required for v2.
    pub amount: Amount,

    /// The script for this output, also known as the scriptPubKey.
    ///
    /// PSBT_OUT_SCRIPT: Excluded for v0, required for v2.
    pub script_pubkey: ScriptBuf,

    /// The X-only pubkey used as the internal key in this output.
    ///
    /// PSBT_OUT_TAP_INTERNAL_KEY: Optional for v0, optional for v2.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot output tree.
    ///
    /// PSBT_OUT_TAP_TREE: Optional for v0, optional for v2.
    pub tap_tree: Option<TapTree>,

    /// Map of Taproot x only keys to origin info and leaf hashes contained in it.
    ///
    /// PSBT_OUT_TAP_BIP32_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Proprietary key-value pairs for this output.
    ///
    /// PSBT_OUT_PROPRIETARY: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    fn to_output() -> bitcoin::psbt::Output {
        todo!()
    }

    fn from_output(output: bitcoin::psbt::Output) -> Result<Output, IsValidPsbtV2Error> {
        assert_is_valid_v2(&output)?;

        Ok(Output {
            redeem_script: output.redeem_script,
            witness_script: output.witness_script,
            bip32_derivation: output.bip32_derivation,
            amount: output.amount.unwrap(),
            script_pubkey: output.script_pubkey.unwrap(),
            tap_internal_key: output.tap_internal_key,
            tap_tree: output.tap_tree,
            tap_key_origins: output.tap_key_origins,
            proprietary: output.proprietary,
            unknown: output.unknown,
        })
    }
}

// TODO: Upstream.
fn assert_is_valid_v2(output: &bitcoin::psbt::Output) -> Result<(), IsValidPsbtV2Error> {
    if output.amount.is_none() {
        return Err(IsValidPsbtV2Error::MissingAmount);
    }
    if output.script_pubkey.is_none() {
        return Err(IsValidPsbtV2Error::MissingScriptPubkey);
    }
    Ok(())
}

/// Output is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsValidPsbtV2Error {
    /// Field `amount` is not set (PSBT_OUT_AMOUNT).
    MissingAmount,
    /// Field `script_pubkey` is not set (PSBT_OUT_SCRIPT).
    MissingScriptPubkey,
}

impl fmt::Display for IsValidPsbtV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IsValidPsbtV2Error::*;

        match *self {
            MissingAmount => write!(
                f,
                "invalid PSBT v2, missing previous amount (PSBT_OUT_AMOUNT)"
            ),
            MissingScriptPubkey => write!(
                f,
                "invalid PSBT v2, missing script pubkey (PSBT_OUT_SCRIPT)"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IsValidPsbtV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IsValidPsbtV2Error::*;

        match *self {
            MissingAmount | MissingScriptPubkey => None,
        }
    }
}
