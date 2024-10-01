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
/// This is similar to `bitcoin::psbt::Input` but with the required PSBTv2 fields non-optional.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    /// The txid of the previous transaction whose output at `self.spent_output_index` is being spent.
    ///
    /// In other words, the output being spent by this `Input` is:
    ///
    ///  `OutPoint { txid: self.previous_txid, vout: self.spent_output_index }`
    pub previous_txid: Txid,

    /// The index of the output being spent in the transaction with the txid of `self.previous_txid`.
    pub spent_output_index: u32,

    /// The sequence number of this input.
    ///
    /// If omitted, assumed to be the final sequence number ([`Sequence::MAX`]).
    pub sequence: Option<Sequence>,

    /// The minimum Unix timestamp that this input requires to be set as the transaction's lock time.
    pub min_time: Option<absolute::Time>,

    /// The minimum block height that this input requires to be set as the transaction's lock time.
    pub min_height: Option<absolute::Height>,

    /// The non-witness transaction this input spends from.
    ///
    /// This should be present for inputs that spend non-segwit outputs and can be present
    /// for inputs that spend segwit outputs.
    pub non_witness_utxo: Option<Transaction>,

    /// The transaction output this input spends from.
    ///
    /// This should only be present for inputs which spend segwit outputs, including
    /// P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-Taproot inputs.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,

    /// The sighash type to be used for this input.
    ///
    /// Signatures for this input must use the sighash type, finalizers must fail to finalize inputs
    /// which have signatures that do not match the specified sighash type.
    pub sighash_type: Option<PsbtSighashType>,

    /// The redeem script for this input if it has one.
    pub redeem_script: Option<ScriptBuf>,

    /// The witnessScript for this input if it has one.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<ScriptBuf>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,

    /// RIPEMD160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,

    /// SHA256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,

    /// HSAH160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,

    /// HAS256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,

    /// Serialized Taproot signature with sighash type for key spend.
    pub tap_key_sig: Option<taproot::Signature>,

    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,

    /// Map of control blocks to script version pair.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Taproot internal key.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Merkle root hash.
    pub tap_merkle_root: Option<TapNodeHash>,
}

impl Input {
    pub(crate) fn from_v2(input: bitcoin::psbt::Input) -> Result<Input, V2InvalidError> {
        assert_is_valid_v2()?;

        let previous_txid = input.previous_txid.unwrap();
        let spent_output_index = input.spent_output_index.unwrap();

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
            previous_txid,
            spent_output_index,
            sequence: input.sequence,
            min_time: input.min_time,
            min_height: input.min_height,
            tap_key_sig: input.tap_key_sig,
            tap_script_sigs: input.tap_script_sigs,
            tap_scripts: input.tap_scripts,
            tap_key_origins: input.tap_key_origins,
            tap_internal_key: input.tap_internal_key,
            tap_merkle_root: input.tap_merkle_root,
        })
    }

    pub(crate) fn from_v0(
        input: bitcoin::psbt::Input,
        prevout: &OutPoint,
    ) -> Result<Input, V0InvalidError> {
        assert_is_valid_v0()?;
        
        let previous_txid = prevout.txid;
        let spent_output_index = prevout.vout;
        
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
            previous_txid,
            spent_output_index,
            sequence: None,
            min_time: None,
            min_height: None,
            tap_key_sig: input.tap_key_sig,
            tap_script_sigs: input.tap_script_sigs,
            tap_scripts: input.tap_scripts,
            tap_key_origins: input.tap_key_origins,
            tap_internal_key: input.tap_internal_key,
            tap_merkle_root: input.tap_merkle_root,
        })
    }
    
    // Converts this input to a `rust-bitcoin` one.
    pub(crate) fn to_v2(self) -> bitcoin::psbt::Input {
        bitcoin::psbt::Input {
            non_witness_utxo: self.non_witness_utxo,
            witness_utxo: self.witness_utxo,
            partial_sigs: self.partial_sigs,
            sighash_type: self.sighash_type,
            redeem_script: self.redeem_script,
            witness_script: self.witness_script,
            bip32_derivation: self.bip32_derivation,
            final_script_sig: self.final_script_sig,
            final_script_witness: self.final_script_witness,
            ripemd160_preimages: self.ripemd160_preimages,
            sha256_preimages: self.sha256_preimages,
            hash160_preimages: self.hash160_preimages,
            hash256_preimages: self.hash256_preimages,
            previous_txid: Some(self.previous_txid),
            spent_output_index: Some(spent_output_index),
            sequence: self.sequence,
            min_time: self.min_time,
            min_height: self.min_height,
            tap_key_sig: self.tap_key_sig,
            tap_script_sigs: self.tap_script_sigs,
            tap_scripts: self.tap_scripts,
            tap_key_origins: self.tap_key_origins,
            tap_internal_key: self.tap_internal_key,
            tap_merkle_root: self.tap_merkle_root,
            proprietary: BTeeMap::default(),
            unknown: BTeeMap::default(),
        }
    }

    // Converts this input to a `rust-bitcoin` one.
    pub(crate) fn to_v0(self) -> bitcoin::psbt::Input {
        let mut input = self.to_v2();
        input.previous_txid = None;
        input.spent_output_index = None;
        input.sequence = None;
        input.min_height = None;
        input.max_height = None;
        input
    }

    /// Returns a [`TxIn`] suitable for the PSBTv0 `unsigned_tx` field.
    pub(crate) fn unsigned_tx_in(&self) -> TxIn {
        TxIn {
            previous_output: self.previous_output,
            script_sig: ScriptBuf::default(),
            sequence: self.sequence.unwrap_or(Sequence::MAX),
            witness: Witness::default(),
        }
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

    /// Returns a reference to the funding utxo for this input.
    pub fn funding_utxo(&self) -> Result<&TxOut, FundingUtxoError> {
        if let Some(ref utxo) = self.witness_utxo {
            Ok(utxo)
        } else if let Some(ref tx) = self.non_witness_utxo {
            let vout = self.spent_output_index as usize;
            tx.output.get(vout).ok_or(FundingUtxoError::OutOfBounds { vout, len: tx.output.len() })
        } else {
            Err(FundingUtxoError::MissingUtxo)
        }
    }

    /// Returns true if this input has been finalized.
    ///
    /// > It checks whether all inputs have complete scriptSigs and scriptWitnesses by checking for
    /// > the presence of 0x07 Finalized scriptSig and 0x08 Finalized scriptWitness typed records.
    ///
    /// Therefore a finalized input must have both `final_script_sig` and `final_script_witness`
    /// fields set. For legacy transactions the `final_script_witness` will be an empty [`Witness`].
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() && self.final_script_witness.is_some()
    }

    /// TODO: Use this.
    #[allow(dead_code)]
    fn has_sig_data(&self) -> bool {
        !(self.partial_sigs.is_empty()
            && self.tap_key_sig.is_none()
            && self.tap_script_sigs.is_empty())
    }

    /// Creates a new finalized input.
    ///
    /// Note the `Witness` is not optional because `miniscript` returns an empty `Witness` in the
    /// case that this is a legacy input.
    ///
    /// The `final_script_sig` and `final_script_witness` should come from `miniscript`.
    #[cfg(feature = "miniscript")]
    pub(crate) fn finalize(
        &self,
        final_script_sig: ScriptBuf,
        final_script_witness: Witness,
    ) -> Result<Input, FinalizeError> {
        debug_assert!(self.has_funding_utxo());

        let mut ret = Input {
            previous_txid: self.previous_txid,
            spent_output_index: self.spent_output_index,
            non_witness_utxo: self.non_witness_utxo.clone(),
            witness_utxo: self.witness_utxo.clone(),

            // Set below.
            final_script_sig: None,
            final_script_witness: None,

            // Clear everything else.
            sequence: None,
            min_time: None,
            min_height: None,
            partial_sigs: BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::new(),
            tap_scripts: BTreeMap::new(),
            tap_key_origins: BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
        };

        // TODO: These errors should only trigger if there are bugs in this crate or miniscript.
        // Is there an infallible way to do this?
        if self.witness_utxo.is_some() {
            if final_script_witness.is_empty() {
                return Err(FinalizeError::EmptyWitness);
            }
            ret.final_script_sig = Some(final_script_sig);
            ret.final_script_witness = Some(final_script_witness);
        } else {
            // TODO: Any checks should do here?
            ret.final_script_sig = Some(final_script_sig);
        }

        Ok(ret)
    }

    // TODO: Work out if this is in line with bip-370
    #[cfg(feature = "miniscript")]
    pub(crate) fn lock_time(&self) -> absolute::LockTime {
        match (self.min_height, self.min_time) {
            // If we have both, bip says use height.
            (Some(height), Some(_)) => height.into(),
            (Some(height), None) => height.into(),
            (None, Some(time)) => time.into(),
            // TODO: Check this is correct.
            (None, None) => absolute::LockTime::ZERO,
        }
    }

    /// Combines this [`Input`] with `other` (as described by BIP-174).
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.previous_txid != other.previous_txid {
            return Err(CombineError::PreviousTxidMismatch {
                this: self.previous_txid,
                that: other.previous_txid,
            });
        }

        if self.spent_output_index != other.spent_output_index {
            return Err(CombineError::SpentOutputIndexMismatch {
                this: self.spent_output_index,
                that: other.spent_output_index,
            });
        }

        // TODO: Should we keep any value other than Sequence::MAX since it is default?
        v2_combine_option!(sequence, self, other);
        v2_combine_option!(min_time, self, other);
        v2_combine_option!(min_height, self, other);
        v2_combine_option!(non_witness_utxo, self, other);

        // TODO: Copied from v0, confirm this is correct.
        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        v2_combine_map!(partial_sigs, self, other);
        // TODO: Why do we not combine sighash_type?
        v2_combine_option!(redeem_script, self, other);
        v2_combine_option!(witness_script, self, other);
        v2_combine_map!(bip32_derivations, self, other);
        v2_combine_option!(final_script_sig, self, other);
        v2_combine_option!(final_script_witness, self, other);
        v2_combine_map!(ripemd160_preimages, self, other);
        v2_combine_map!(sha256_preimages, self, other);
        v2_combine_map!(hash160_preimages, self, other);
        v2_combine_map!(hash256_preimages, self, other);
        v2_combine_option!(tap_key_sig, self, other);
        v2_combine_map!(tap_script_sigs, self, other);
        v2_combine_map!(tap_scripts, self, other);
        v2_combine_map!(tap_key_origins, self, other);
        v2_combine_option!(tap_internal_key, self, other);
        v2_combine_option!(tap_merkle_root, self, other);

        Ok(())
    }

}

/// Asserts this input is valid as required for PSBT v2.
// TODO: Upstream.
pub(crate) fn assert_is_valid_v2(input: &bitcoin::psbt::Input) -> Result<(), V2InvalidError> {
    use V2InvalidError::*;

    if input.previous_txid.is_none() {
        return Err(MissingPreviousTxid);
    }
    if input.spent_output_index.is_none() {
        return Err(MissingSpentOutputIndex);
    }

    Ok(())
}

/// Input is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2InvalidError {
    /// Field `previous_txid` is not set (PSBT_IN_PREVIOUS_TXID).
    MissingPreviousTxid,
    /// Field `spent_output_index` is not set (PSBT_IN_OUTPUT_INDEX).
    MissingSpentOutputIndex,
}

impl fmt::Display for V2InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use V2InvalidError::*;

        match *self {
            MissingPreviousTxid =>
                write!(f, "invalid PSBT v2, missing previous txid (PSBT_IN_PREVIOUS_TXID)"),
            MissingSpentOutputIndex =>
                write!(f, "invalid PSBT v2, missing spent output index (PSBT_IN_OUTPUT_INDEX)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V2InvalidError::*;

        match *self {
            MissingPreviousTxid | MissingSpentOutputIndex => None,
        }
    }
}

// TODO: Upstream.
pub(crate) fn assert_is_valid_v0(input: &bitcoin::psbt::Input) -> Result<(), V0InvalidError> {
    use V0InvalidError::*;

    if input.sequence.is_some() {
        return Err(HasSequence);
    }
    if input.min_time.is_some() {
        return Err(HasMinTime);
    }
    if input.min_height.is_some() {
        return Err(HasMinHeight);
    }

    Ok(())
}

/// Input is not valid according to the Version 0 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0InvalidError {
    /// Field `sequence` should be excluded for v0 (PSBT_IN_SEQUENCE).
    HasSequence,
    /// Field `min_time` should be excluded for v0 (PSBT_IN_REQUIRED_TIME_LOCKTIME).
    HasMinTime,
    /// Field `min_height` should be excluded for v0 (PSBT_IN_REQUIRED_HEIGHT_LOCKTIME).
    HasMinHeight,
}

impl fmt::Display for V0InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IsValidPsbtV2Error::*;

        match *self {
            HasSequence =>
                write!(f, "invalid v2 input, `sequence` should be excluded (PSBT_IN_SEQUENCE)"),
            HasMinTime =>
                write!(f, "invalid v2 input, `min_time` should be excluded (PSBT_IN_REQUIRED_TIME_LOCKTIME)"),
            HasMinHeight =>
                write!(f, "invalid v2 input, `min_height` should be excluded (PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V0InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V0InvalidError::*;

        match *self {
            HasSequence | HasMinTime | HasMinHeight => None,
        }
    }
}
