// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
//! PSBT version 2 as defined in [BIP-370].
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
mod output;
mod roles;
#[cfg(feature = "serde")]
mod serde_utils;

use core::fmt;

use bitcoin_internals::write_err;

use bitcoin::bip32::{KeySource, Xpub};
use bitcoin::psbt::raw;
use bitcoin::{absolute, transaction};

use crate::error::DetermineLockTimeError;
use crate::prelude::BTreeMap;

#[rustfmt::skip]                // Keep public exports separate.
#[doc(inline)]
pub use self::{
    input::Input,
    output::Output,
    roles::{Creator, Constructor}, //, Updater, Signer, Finalizer, Extractor};
};

/// The Inputs Modifiable Flag, set to 1 to indicate whether inputs can be added or removed.
const INPUTS_MODIFIABLE: u8 = 0x01 << 0;

/// The Outputs Modifiable Flag, set to 1 to indicate whether outputs can be added or removed.
const OUTPUTS_MODIFIABLE: u8 = 0x01 << 1;

/// The Has SIGHASH_SINGLE flag, set to 1 to indicate whether the transaction has a SIGHASH_SINGLE
/// signature who's input and output pairing must be preserved. Essentially indicates that the
/// Constructor must iterate the inputs to determine whether and how to add or remove an input.
const SIGHASH_SINGLE: u8 = 0x01 << 2;

/// A PSBT guaranteed to be valid for PSBT version 2.
///
/// This is an exact copy of `bitcoin::psbt::Input` but with the required PSBT fields non-optional.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Psbt {
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    ///
    /// PSBT_GLOBAL_XPUB: Optional for v0, optional for v2.
    pub xpub: BTreeMap<Xpub, KeySource>,

    /// The version number of the transaction being built.
    ///
    /// PSBT_GLOBAL_TX_VERSION: Excluded for v0, required for v2.
    pub tx_version: transaction::Version,

    /// The transaction locktime to use if no inputs specify a required locktime.
    ///
    /// PSBT_GLOBAL_FALLBACK_LOCKTIME: Excluded for v0, optional for v2.
    pub fallback_lock_time: absolute::LockTime,

    /// The number of inputs in this PSBT.
    ///
    /// PSBT_GLOBAL_INPUT_COUNT: Excluded for v0, required for v2.
    pub input_count: usize, // Serialized as compact int.

    /// The number of outputs in this PSBT.
    ///
    /// PSBT_GLOBAL_OUTPUT_COUNT: Excluded for v0, required for v2.
    pub output_count: usize, // Serialized as compact int.

    /// A bitfield for various transaction modification flags.
    ///
    /// PSBT_GLOBAL_TX_MODIFIABLE: Excluded for v0, optional for v2.
    pub tx_modifiable_flags: u8,

    /// The version number of this PSBT (if omitted defaults to version 0).
    ///
    /// PSBT_GLOBAL_VERSION: Optional for v0, optional for v2.
    pub version: u32, // This is not an option because if omitted it is implied to be 0.

    /// Global proprietary key-value pairs.
    ///
    /// PSBT_GLOBAL_PROPRIETARY: Optional for v0, optional for v2.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown global key-value pairs.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,

    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    /// Creates a new empty PSBT.
    pub fn empty() -> Self {
        Psbt {
            xpub: BTreeMap::default(),
            tx_version: transaction::Version::TWO,
            fallback_lock_time: absolute::LockTime::ZERO,
            input_count: 0,
            output_count: 0,
            tx_modifiable_flags: 0, // Default to non-modifiable.
            version: 0,
            proprietary: BTreeMap::default(),
            unknown: BTreeMap::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    /// Converts this crate's `Psbt` type to the `rust-bitcoin` one.
    ///
    /// # Returns
    ///
    /// A `bitcoin::Psbt` type with the correct fields to serialize as Version 2.
    pub fn to_psbt(self) -> bitcoin::Psbt {
        self.to_psbt_v2()
    }

    /// Converts this crate's `Psbt` type to the `rust-bitcoin` one.
    ///
    /// # Returns
    ///
    /// A `bitcoin::Psbt` type with the correct fields to serialize as Version 0.
    pub fn to_psbt_v0(self) -> bitcoin::Psbt {
        todo!()
    }

    /// Converts this crate's `Psbt` type to the `rust-bitcoin` one.
    ///
    /// # Returns
    ///
    /// A `bitcoin::Psbt` type with the correct fields to serialize as Version 2.
    pub fn to_psbt_v2(self) -> bitcoin::Psbt {
        todo!()
    }

    fn from_psbt(psbt: bitcoin::Psbt) -> Result<Psbt, IsValidPsbtV2Error> {
        assert_is_valid_v2(&psbt)?;
        todo!()
    }

    fn set_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= INPUTS_MODIFIABLE;
    }

    fn set_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= OUTPUTS_MODIFIABLE;
    }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    fn set_sighash_single_flag(&mut self) {
        self.tx_modifiable_flags |= SIGHASH_SINGLE;
    }

    fn clear_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !INPUTS_MODIFIABLE;
    }

    fn clear_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !OUTPUTS_MODIFIABLE;
    }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    fn clear_sighash_single_flag(&mut self) {
        self.tx_modifiable_flags &= !SIGHASH_SINGLE;
    }

    fn is_inputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & INPUTS_MODIFIABLE > 0
    }

    fn is_outputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & OUTPUTS_MODIFIABLE > 0
    }

    // TODO: Investigate if we should be using this function?
    #[allow(dead_code)]
    fn has_sighash_single(&self) -> bool {
        self.tx_modifiable_flags & SIGHASH_SINGLE > 0
    }

    /// Determines the lock time as specified in [BIP-370] if it is possible to do so.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time>
    fn determine_lock_time(&self) -> Result<absolute::LockTime, DetermineLockTimeError> {
        let require_time_based_lock_time = self
            .inputs
            .iter()
            .any(|input| input.requires_time_based_lock_time());
        let require_height_based_lock_time = self
            .inputs
            .iter()
            .any(|input| input.requires_height_based_lock_time());

        if require_time_based_lock_time && require_height_based_lock_time {
            return Err(DetermineLockTimeError);
        }

        let have_lock_time = self.inputs.iter().any(|input| input.has_lock_time());

        let lock = if have_lock_time {
            let all_inputs_satisfied_with_height_based_lock_time = self
                .inputs
                .iter()
                .all(|input| input.is_satisfied_with_height_based_lock_time());

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
fn assert_is_valid_v2(psbt: &bitcoin::Psbt) -> Result<(), IsValidPsbtV2Error> {
    if psbt.tx_version.is_none() {
        return Err(IsValidPsbtV2Error::MissingTxVersion);
    }

    if psbt.input_count.is_none() {
        return Err(IsValidPsbtV2Error::MissingInputCount);
    }

    if psbt.output_count.is_none() {
        return Err(IsValidPsbtV2Error::MissingOutputCount);
    }

    Ok(())
}

/// PSBT is not valid according to the Version 2 requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsValidPsbtV2Error {
    /// Field `tx_version` is not set (PSBT_GLOBAL_TX_VERSION).
    MissingTxVersion,
    /// Field `input_count` is not set (PSBT_GLOBAL_INPUT_COUNT).
    MissingInputCount,
    /// Field `output_count` is not set (PSBT_GLOBAL_OUTPUT_COUNT).
    MissingOutputCount,
    /// Invalid PSBT v2 input.
    InvalidInput(usize, input::IsValidPsbtV2Error),
    /// Invalid PSBT v2 output.
    InvalidOutput(usize, output::IsValidPsbtV2Error),
}

impl fmt::Display for IsValidPsbtV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IsValidPsbtV2Error::*;

        match *self {
            MissingTxVersion => write!(
                f,
                "invalid PSBT v2, missing tx version (PSBT_GLOBAL_TX_VERSION)"
            ),
            MissingInputCount => write!(
                f,
                "invalid PSBT v2, missing input count (PSBT_GLOBAL_INPUT_COUNT)"
            ),
            MissingOutputCount => write!(
                f,
                "invalid PSBT v2, missing output count (PSBT_GLOBAL_OUTPUT_COUNT)"
            ),
            InvalidInput(index, ref e) => write_err!(f, "invalid input for index {}", index; e),
            InvalidOutput(index, ref e) => write_err!(f, "invalid output for index {}", index; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IsValidPsbtV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IsValidPsbtV2Error::*;

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
