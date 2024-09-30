// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::{raw, PsbtSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{
    absolute, ecdsa, secp256k1, taproot, PublicKey, ScriptBuf, Sequence, Transaction, TxOut, Txid,
    Witness,
};

use crate::prelude::BTreeMap;

/// A PSBT input guaranteed to be valid for PSBT version 2.
///
/// This is an exact copy of `bitcoin::psbt::Input` but with the required PSBT fields non-optional.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    /// The non-witness transaction this input spends from.
    ///
    /// This should be present for inputs that spend non-segwit outputs and can be present
    /// for inputs that spend segwit outputs.
    ///
    /// PSBT_IN_NON_WITNESS_UTXO: Optional for v0, optional for v2.
    pub non_witness_utxo: Option<Transaction>,

    /// The transaction output this input spends from.
    ///
    /// This should only be present for inputs which spend segwit outputs, including
    /// P2SH embedded ones.
    ///
    /// PSBT_IN_WITNESS_UTXO: Optional for v0, optional for v2.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-Taproot inputs.
    ///
    /// PSBT_IN_PARTIAL_SIG: Optional for v0, optional for v2.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,

    /// The sighash type to be used for this input.
    ///
    /// Signatures for this input must use the sighash type, finalizers must fail to finalize inputs
    /// which have signatures that do not match the specified sighash type.
    ///
    /// PSBT_IN_SIGHASH_TYPE: Optional for v0, optional for v2.
    pub sighash_type: Option<PsbtSighashType>,

    /// The redeem script for this input if it has one.
    ///
    /// PSBT_IN_REDEEM_SCRIPT: Optional for v0, optional for v2.
    pub redeem_script: Option<ScriptBuf>,

    /// The witnessScript for this input if it has one.
    ///
    /// PSBT_IN_WITNESS_SCRIPT: Optional for v0, optional for v2.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    ///
    /// PSBT_IN_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    ///
    /// PSBT_IN_SCRIPTSIG: Optional for v0, optional for v2.
    pub final_script_sig: Option<ScriptBuf>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    ///
    /// PSBT_IN_SCRIPTWITNESS: Optional for v0, optional for v2.
    pub final_script_witness: Option<Witness>,

    /// RIPEMD160 hash to preimage map.
    ///
    /// PSBT_IN_RIPEMD160: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,

    /// SHA256 hash to preimage map.
    ///
    /// PSBT_IN_SHA256: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,

    /// HSAH160 hash to preimage map.
    ///
    /// PSBT_IN_HASH160: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,

    /// HAS256 hash to preimage map.
    ///
    /// PSBT_IN_HASH256: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,

    /// The txid of the previous transaction whose output at `self.spent_output_index` is being spent.
    ///
    /// In other words, the output being spent by this `Input` is:
    ///
    ///  `OutPoint { txid: self.previous_txid, vout: self.spent_output_index }`
    ///
    /// PSBT_IN_PREVIOUS_TXID: Excluded for v0, required for v2.
    pub previous_txid: Txid,

    /// The index of the output being spent in the transaction with the txid of `self.previous_txid`.
    ///
    /// PSBT_IN_OUTPUT_INDEX: Excluded for v0, required for v2.
    pub spent_output_index: u32,

    /// The sequence number of this input.
    ///
    /// If omitted, assumed to be the final sequence number ([`Sequence::MAX`]).
    ///
    /// PSBT_IN_SEQUENCE: Excluded for v0, optional for v2.
    pub sequence: Option<Sequence>,

    /// The minimum Unix timestamp that this input requires to be set as the transaction's lock time.
    ///
    /// PSBT_IN_REQUIRED_TIME_LOCKTIME: Excluded for v0, optional for v2.
    pub min_time: Option<absolute::Time>,

    /// The minimum block height that this input requires to be set as the transaction's lock time.
    ///
    /// PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: Excluded for v0, optional for v2.
    pub min_height: Option<absolute::Height>,

    /// Serialized Taproot signature with sighash type for key spend.
    ///
    /// PSBT_IN_TAP_SCRIPT_SIG: Optional for v0, optional for v2.
    pub tap_key_sig: Option<taproot::Signature>,

    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    ///
    /// PSBT_IN_TAP_SCRIPT_SIG: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,

    /// Map of control blocks to script version pair.
    ///
    /// PSBT_IN_TAP_LEAF_SCRIPT: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    ///
    /// PSBT_IN_TAP_BIP32_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Taproot internal key.
    ///
    /// PSBT_IN_TAP_INTERNAL_KEY: Optional for v0, optional for v2.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Merkle root hash.
    ///
    /// PSBT_IN_TAP_MERKLE_ROOT: Optional for v0, optional for v2.
    pub tap_merkle_root: Option<TapNodeHash>,

    /// Proprietary key-value pairs for this input.
    ///
    /// PSBT_IN_PROPRIETARY: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this input.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Input {
    fn to_input() -> bitcoin::psbt::Input {
        todo!()
    }

    fn from_input(input: bitcoin::psbt::Input) -> Result<Input, IsValidPsbtV2Error> {
        assert_is_valid_v2(&input)?;

        Ok(Input {
            non_witness_utxo: input.non_witness_utxo,
            witness_utxo: input.witness_utxo,
            partial_sigs: input.partial_sigs,
            sighash_type: input.sighash_type,
            redeem_script: input.redeem_script,
            witness_script: input.witness_script,
            bip32_derivation: input.bip32_derivation,
            final_script_sig: input.final_script_sig,
            final_script_witness: input.final_script_witness,
            ripemd160_preimages: input.ripemd160_preimages,
            sha256_preimages: input.sha256_preimages,
            hash160_preimages: input.hash160_preimages,
            hash256_preimages: input.hash256_preimages,
            previous_txid: input.previous_txid.unwrap(),
            spent_output_index: input.spent_output_index.unwrap(),
            sequence: input.sequence,
            min_time: input.min_time,
            min_height: input.min_height,
            tap_key_sig: input.tap_key_sig,
            tap_script_sigs: input.tap_script_sigs,
            tap_scripts: input.tap_scripts,
            tap_key_origins: input.tap_key_origins,
            tap_internal_key: input.tap_internal_key,
            tap_merkle_root: input.tap_merkle_root,
            proprietary: input.proprietary,
            unknown: input.unknown,
        })
    }

    pub(crate) fn has_lock_time(&self) -> bool {
        self.min_time.is_some() || self.min_height.is_some()
    }

    pub(crate) fn is_satisfied_with_height_based_lock_time(&self) -> bool {
        self.requires_height_based_lock_time()
            || self.min_time.is_some() && self.min_height.is_some()
            || self.min_time.is_none() && self.min_height.is_none()
    }

    pub(crate) fn requires_time_based_lock_time(&self) -> bool {
        self.min_time.is_some() && self.min_height.is_none()
    }

    pub(crate) fn requires_height_based_lock_time(&self) -> bool {
        self.min_height.is_some() && self.min_time.is_none()
    }
}

// TODO: Upstream.
fn assert_is_valid_v2(input: &bitcoin::psbt::Input) -> Result<(), IsValidPsbtV2Error> {
    if input.previous_txid.is_none() {
        return Err(IsValidPsbtV2Error::MissingPreviousTxid);
    }
    if input.spent_output_index.is_none() {
        return Err(IsValidPsbtV2Error::MissingSpentOutputIndex);
    }
    Ok(())
}

/// Input is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsValidPsbtV2Error {
    /// Field `previous_txid` is not set (PSBT_IN_PREVIOUS_TXID).
    MissingPreviousTxid,
    /// Field `spent_output_index` is not set (PSBT_IN_OUTPUT_INDEX).
    MissingSpentOutputIndex,
}

impl fmt::Display for IsValidPsbtV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IsValidPsbtV2Error::*;

        match *self {
            MissingPreviousTxid => write!(
                f,
                "invalid PSBT v2, missing previous txid (PSBT_IN_PREVIOUS_TXID)"
            ),
            MissingSpentOutputIndex => write!(
                f,
                "invalid PSBT v2, missing spent output index (PSBT_IN_OUTPUT_INDEX)"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IsValidPsbtV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IsValidPsbtV2Error::*;

        match *self {
            MissingPreviousTxid | MissingSpentOutputIndex => None,
        }
    }
}
