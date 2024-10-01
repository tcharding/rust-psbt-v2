// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transaction Version 2.
//!
//! PSBT v2 as defined in [BIP-174] and [BIP-370].
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

extern crate alloc;

/// Re-export of the `rust-bitcoin` crate.
pub extern crate bitcoin;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod error;
mod input;
#[macro_use]
mod macros;
mod output;
mod roles;
#[cfg(feature = "serde")]
mod serde_utils;

use core::fmt;

use bitcoin::bip32::{KeySource, Xpub};
use bitcoin::psbt::raw;
use bitcoin::{absolute, transaction};
use bitcoin_internals::write_err;

use crate::error::DetermineLockTimeError;
use crate::prelude::BTreeMap;

#[rustfmt::skip]                // Keep public exports separate.
#[doc(inline)]
pub use self::{
    input::Input,
    output::Output,
    roles::{Creator, Constructor, Updater, Signer, Extractor},
};
#[cfg(feature = "miniscript")]
pub use self::roles::Finalizer;

/// The Inputs Modifiable Flag, set to 1 to indicate whether inputs can be added or removed.
const INPUTS_MODIFIABLE: u8 = 0x01 << 0;

/// The Outputs Modifiable Flag, set to 1 to indicate whether outputs can be added or removed.
const OUTPUTS_MODIFIABLE: u8 = 0x01 << 1;

/// The has SIGHASH_SINGLE flag, set to 1 to indicate whether the transaction has a SIGHASH_SINGLE
/// signature who's input and output pairing must be preserved. Essentially indicates that the
/// Constructor must iterate the inputs to determine whether and how to add or remove an input.
const SIGHASH_SINGLE: u8 = 0x01 << 2;

/// Combines these two PSBTs as described by BIP-174 (i.e. combine is the same for BIP-370).
///
/// This function is commutative `combine(this, that) = combine(that, this)`.
pub fn combine(this: Psbt, that: Psbt) -> Result<Psbt, CombineError> { this.combine_with(that) }
// TODO: Consider adding an iterator API that combines a list of PSBTs.

/// A version 2 PSBT.
///
/// Note this struct does not have a PSBT version field because it is implicitly v2 unless
/// explicitly converting to a `bitcoin::psbt::Psbt` at which time the version number can be set.
// FIXME: Are these derives correct (Hash and not Ord)?
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Psbt {
    /// The version number of the transaction being built.
    pub tx_version: transaction::Version,

    /// The transaction locktime to use if no inputs specify a required locktime.
    pub fallback_lock_time: absolute::LockTime,

    /// The number of inputs in this PSBT.
    pub input_count: usize,

    /// The number of outputs in this PSBT.
    pub output_count: usize,

    /// A bitfield for various transaction modification flags.
    ///
    /// If omitted defaults to 0 i.e., non-modifiable.
    pub tx_modifiable_flags: u8,

    /// Map BIP-32 extended public keys to the used key fingerprint and derivation path.
    pub xpub: BTreeMap<Xpub, KeySource>,

    /// The PSBT inputs.
    pub inputs: Vec<Input>,

    /// The PSBT outputs.
    pub outputs: Vec<Output>,
}

impl Psbt {
    /// Serialize PSBT as binary data.
    pub fn serialize(&self) -> Vec<u8> { self.to_psbt().serialize() }

    /// Serialize PSBT as a lowercase hex string.
    pub fn serialize_hex(&self) -> String { self.to_psbt().serialize_hex() }

    /// Serialize the PSBT into a writer.
    pub fn serialize_to_writer(&self, w: &mut impl Write) -> io::Result<usize> { self.to_psbt().serialize_to_writer(w) }

    /// Deserialize PSBT from binary data.
    pub fn deserialize(mut bytes: &[u8]) -> Result<Self, DeserializeError> {
        let psbt = bitcoin::psbt::Psbt::deserialize(bytes)?;
        Ok(Psbt::from_psbt(psbt)?)
    }

    // TODO: Implement Psbt::deserialize_hex function upstream.
    //
    // /// Deserialize PSBT from a hex string.
    // pub fn deserialize_hex(mut psbt: &str) -> Result<Self, DeserializeError> {
    //     let psbt = bitcoin::psbt::Psbt::deserialize_hex(bytes)?;
    //     Ok(Psbt::from_psbt(psbt)?)
    // }

    /// Deserialize a value from raw binary data read from a `BufRead` object.
    pub fn deserialize_from_reader<R: io::BufRead>(r: &mut R) -> Result<Self, DeserializeError> {
        let psbt = bitcoin::psbt::Psbt::deserialize_from_reader(r)?;
        Ok(Psbt::from_psbt(psbt)?)
    }

    /// Converts a `rust-bitcoin` PSBT into this crates `Psbt` type.
    pub fn from_psbt(psbt: bitcoin::Psbt) -> Result<Psbt, InvalidError> {
        match psbt.version {
            0 => Ok(Self::from_psbt_v0(psbt)?),
            2 => Ok(Self::from_psbt_v2(psbt)?),
            other => Err(InvalidError::UnsupportedVersion(other)),
        }
    }

    /// Converts a `rust-bitcoin` PSBT into this crates `Psbt` type.
    fn from_v0(psbt: bitcoin::Psbt) -> Result<Psbt, V0InvalidError> {
        assert_is_valid_v0(psbt)?;

        let tx = psbt.unsigned_tx.unwrap();
        let input_count = tx.input.len();
        let output_count = tx.output.len();

        Ok(Psbt {
            tx_version: transaction::Version::TWO, // TODO: Check this is correct.
            fallback_lock_time: absolute::LockTime::ZERO,
            input_count,
            output_count,
            tx_modifiable_flags: 0,
            xpub: psbt.xpub,
            inputs: psbt.inputs.iter().map(|input| input.from_v0()),
            outputs: psbt.outputs.iter().map(|output| output.from_v0())
        })
    }

    /// Converts a `rust-bitcoin` PSBT into this crates `Psbt` type.
    fn from_v2(psbt: bitcoin::Psbt) -> Result<Psbt, V2InvalidError> {
        assert_is_valid_v2(psbt)?;

        Ok(Psbt {
            tx_version: psbt.tx_version.unwrap(),
            fallback_lock_time: psbt.fallback_lock_time.unwrap_or(absolute::LockTime::ZERO),
            input_count: psbt.input_count.unwrap(),
            output_count: psbt.output_count.unwrap(),
            tx_modifiable_flags: psbt.tx_modifiable_flags.unwrap_or(0),
            xpub: psbt.xpub,
            inputs: psbt.inputs.iter().map(|input| input.from_v2()),
            outputs: psbt.outputs.iter().map(|output| output.from_v2()),
        })
    }

    /// Converts this crate's `Psbt` type to the `rust-bitcoin` one.
    ///
    /// # Returns
    ///
    /// A `bitcoin::Psbt` type with the correct fields to serialize as Version 2.
    pub fn to_psbt(self) -> bitcoin::Psbt { self.to_psbt_v2() }

    /// Converts this crate's `Psbt` type to the `rust-bitcoin` one.
    ///
    /// # Returns
    ///
    /// A `bitcoin::Psbt` type with the correct fields to serialize as Version 0.
    pub fn to_psbt_v0(self) -> bitcoin::Psbt {
        let version = 0;
        let unsigned_tx = self.unsigned_tx();

        bitcoin::Psbt {
            unsigned_tx: Some(unsigned_tx),
            xpub: self.xpub,
            tx_version: self.tx_version,
            fallback_lock_time: None,
            input_count: None,
            output_count: None,
            tx_modifiable_flags: None,
            version,
            proprietary: BTeeMap::default(),
            unknown: BTeeMap::default(),
            inputs: self.inputs.iter().map(|input| input.to_v0()),
            outputs: self.outputs.iter().map(|output| output.to_v0())
        }
    }

    /// Converts this crate's `Psbt` type to the `rust-bitcoin` one.
    ///
    /// # Returns
    ///
    /// A `bitcoin::Psbt` type with the correct fields to serialize as Version 2.
    pub fn to_psbt_v2(self) -> bitcoin::Psbt {
        let version = 2;

        bitcoin::Psbt {
            unsigned_tx: None,
            xpub: self.xpub,
            tx_version: self.tx_version,
            fallback_lock_time: Some(self.fallback_lock_time),
            input_count: Some(self.input_count),
            output_count: Some(self.output_count),
            tx_modifiable_flags: Some(self.tx_modifiable_flags),
            version,
            proprietary: BTeeMap::default(),
            unknown: BTeeMap::default(),
            inputs: self.inputs.iter().map(|input| input.to_v2()),
            outputs: self.outputs.iter().map(|output| output.to_v2())
        }
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP-174.
    ///
    /// BIP-370 does not include any additional requirements for the Combiner role.
    ///
    /// This function is commutative `A.combine_with(B) = B.combine_with(A)`.
    ///
    /// See [`combine()`] for a non-consuming version of this function.
    pub fn combine_with(mut self, other: Self) -> Result<Psbt, CombineError> {
        self.global.combine(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output)?;
        }

        Ok(self)
    }


    /// Combines [`Global`] with `other`.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        // No real reason to support this.
        if self.tx_version != other.tx_version {
            return Err(CombineError::TxVersionMismatch {
                this: self.tx_version,
                that: other.tx_version,
            });
        }

        // TODO: Check the bip, I just guessed these.
        self.input_count += other.input_count;
        self.output_count += other.output_count;

        // TODO: What to do about
        // - fallback_lock_time
        // - tx_modifiable_flags

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpubs {
            match self.xpubs.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(InconsistentKeySourcesError(xpub).into());
                }
            }
        }

        Ok(())
    }
    
    fn set_inputs_modifiable_flag(&mut self) { self.tx_modifiable_flags |= INPUTS_MODIFIABLE; }

    fn set_outputs_modifiable_flag(&mut self) { self.tx_modifiable_flags |= OUTPUTS_MODIFIABLE; }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    fn set_sighash_single_flag(&mut self) { self.tx_modifiable_flags |= SIGHASH_SINGLE; }

    fn clear_inputs_modifiable_flag(&mut self) { self.tx_modifiable_flags &= !INPUTS_MODIFIABLE; }

    fn clear_outputs_modifiable_flag(&mut self) { self.tx_modifiable_flags &= !OUTPUTS_MODIFIABLE; }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    fn clear_sighash_single_flag(&mut self) { self.tx_modifiable_flags &= !SIGHASH_SINGLE; }

    fn is_inputs_modifiable(&self) -> bool { self.tx_modifiable_flags & INPUTS_MODIFIABLE > 0 }

    fn is_outputs_modifiable(&self) -> bool { self.tx_modifiable_flags & OUTPUTS_MODIFIABLE > 0 }

    // TODO: Investigate if we should be using this function?
    #[allow(dead_code)]
    fn has_sighash_single(&self) -> bool { self.tx_modifiable_flags & SIGHASH_SINGLE > 0 }

    /// Returns this PSBT's unique identification.
    fn id(&self) -> Result<Txid, DetermineLockTimeError> {
        let mut tx = self.unsigned_tx()?;
        // Updaters may change the sequence so to calculate ID we set it to zero.
        tx.input.iter_mut().for_each(|input| input.sequence = Sequence::ZERO);

        Ok(tx.compute_txid())
    }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    ///
    /// This function is solely for creating the `unsigned_tx` field of a PSBTv0, it should not be
    /// used to determine the ID of the `Psbt`, use `Self::id()` instead.
    fn unsigned_tx(&self) -> Result<Transaction, DetermineLockTimeError> {
        let lock_time = self.determine_lock_time()?;

        Ok(Transaction {
            version: self.tx_version,
            lock_time,
            input: self.inputs.iter().map(|input| input.unsigned_tx_in()).collect(),
            output: self.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        })
    }

    /// Determines the lock time as specified in [BIP-370] if it is possible to do so.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time>
    fn determine_lock_time(&self) -> Result<absolute::LockTime, DetermineLockTimeError> {
        let require_time_based_lock_time =
            self.inputs.iter().any(|input| input.requires_time_based_lock_time());
        let require_height_based_lock_time =
            self.inputs.iter().any(|input| input.requires_height_based_lock_time());

        if require_time_based_lock_time && require_height_based_lock_time {
            return Err(DetermineLockTimeError);
        }

        let have_lock_time = self.inputs.iter().any(|input| input.has_lock_time());

        let lock = if have_lock_time {
            let all_inputs_satisfied_with_height_based_lock_time =
                self.inputs.iter().all(|input| input.is_satisfied_with_height_based_lock_time());

            // > The lock time chosen is then the maximum value of the chosen type of lock time.
            if all_inputs_satisfied_with_height_based_lock_time {
                // We either have only height based or we have both, in which case we must use height based.
                let height = self
                    .inputs
                    .iter()
                    .map(|input| input.min_height)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(height)
            } else {
                let time = self
                    .inputs
                    .iter()
                    .map(|input| input.min_time)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(time)
            }
        } else {
            // > If none of the inputs have a PSBT_IN_REQUIRED_TIME_LOCKTIME and
            // > PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, then PSBT_GLOBAL_FALLBACK_LOCKTIME must be used.
            // > If PSBT_GLOBAL_FALLBACK_LOCKTIME is not provided, then it is assumed to be 0.
            self.fallback_lock_time
        };

        Ok(lock)
    }
}

// TODO: Upstream.
fn assert_is_valid_v2(psbt: &bitcoin::Psbt) -> Result<(), V2InvalidError> {
    use V2InvalidError::*;

    if psbt.tx_version.is_none() {
        return Err(MissingTxVersion);
    }

    if psbt.input_count.is_none() {
        return Err(MissingInputCount);
    }

    if psbt.output_count.is_none() {
        return Err(MissingOutputCount);
    }

    Ok(())
}

/// PSBT deserialization error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeserializeError {
    Deserialize(bitcoin::psbt::Error),
    Invalid(InvalidError),
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DeserializeError::*;

        match *self {
            Deserialize(ref e) => write_err!(f, "deserialize"; e),
            Invalid(ref e) => write_err!(f, "deserialize"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DeserializeError::*;

        match *self {
            Deserialize(ref e) => Some(e),
            Invalid(ref e) => Some(e),
        }
    }
}

/// PSBT is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidError {
    /// PSBT invalid version 0.
    V0Invalid(V0InvalidError),
    /// PSBT invalid version 2.
    V2Invalid(V2InvalidError),
    /// Unsupported PSBT version number.
    UnsupportedVersion(u32),
}

impl fmt::Display for InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InvalidError::*;

        match *self {
            V0Invalid(ref e) => write_err!(f, "invalid PSBT"; e),
            V2Invalid(ref e) => write_err!(f, "invalid PSBT"; e),
            UnsupportedVersion(v) => write!(f, "unsupported psbt version {}", v),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InvalidError::*;

        match *self {
            V0Invalid(ref e) => Some(e),
            V2Invalid(ref e) => Some(e),
            UnsupportedVersion(_) => None,
        }
    }
}

/// PSBT is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2InvalidError {
    /// Field `tx_version` is not set (PSBT_GLOBAL_TX_VERSION).
    MissingTxVersion,
    /// Field `input_count` is not set (PSBT_GLOBAL_INPUT_COUNT).
    MissingInputCount,
    /// Field `output_count` is not set (PSBT_GLOBAL_OUTPUT_COUNT).
    MissingOutputCount,
    /// Invalid PSBT v2 input.
    InvalidInput(usize, input::V2InvalidError),
    /// Invalid PSBT v2 output.
    InvalidOutput(usize, output::V2InvalidError),
}

impl fmt::Display for V2InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use V2InvalidError::*;

        match *self {
            MissingTxVersion =>
                write!(f, "invalid PSBT v2, missing tx version (PSBT_GLOBAL_TX_VERSION)"),
            MissingInputCount =>
                write!(f, "invalid PSBT v2, missing input count (PSBT_GLOBAL_INPUT_COUNT)"),
            MissingOutputCount =>
                write!(f, "invalid PSBT v2, missing output count (PSBT_GLOBAL_OUTPUT_COUNT)"),
            InvalidInput(index, ref e) => write_err!(f, "invalid input for index {}", index; e),
            InvalidOutput(index, ref e) => write_err!(f, "invalid output for index {}", index; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V2InvalidError::*;

        match *self {
            InvalidInput(_index, ref e) => Some(e),
            InvalidOutput(_index, ref e) => Some(e),
            MissingTxVersion | MissingInputCount | MissingOutputCount => None,
        }
    }
}

#[rustfmt::skip]
mod prelude {
    #![allow(unused_imports)]

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), target_has_atomic = "ptr"))]
    pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};
}
