// SPDX-License-Identifier: CC0-1.0l

//! The PSBT Version 2 Creator role.

use bitcoin::{absolute, transaction};

use crate::roles::constructor::{
    Constructor, InputsOnlyModifiable, Modifiable, OutputsOnlyModifiable,
};
use crate::Psbt;

/// Implements the BIP-370 Creator role.
///
/// The `Creator` type is only directly needed if one of the following holds:
///
/// - The creator and constructor are separate entities.
/// - You need to set the fallback lock time.
/// - You need to set the sighash single flag.
///
/// If not use the [`Constructor`]  to carry out both roles e.g., `Constructor::<Modifiable>::default()`.
///
/// See `examples/v2-separate-creator-constructor.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Creator(Psbt);

impl Creator {
    /// Creates a new PSBT Creator with an empty `Psbt`.
    pub fn new() -> Self {
        Creator(Psbt::empty())
    }

    /// Sets the fallback lock time.
    pub fn fallback_lock_time(mut self, fallback: absolute::LockTime) -> Self {
        self.0.fallback_lock_time = fallback;
        self
    }

    /// Sets the "has sighash single" flag in then transaction modifiable flags.
    pub fn sighash_single(mut self) -> Self {
        self.0.set_sighash_single_flag();
        self
    }

    /// Sets the inputs modifiable bit in the transaction modifiable flags.
    pub fn inputs_modifiable(mut self) -> Self {
        self.0.set_inputs_modifiable_flag();
        self
    }

    /// Sets the outputs modifiable bit in the transaction modifiable flags.
    pub fn outputs_modifiable(mut self) -> Self {
        self.0.set_outputs_modifiable_flag();
        self
    }

    /// Sets the transaction version.
    ///
    /// You likely do not need this, it is provided for completeness.
    ///
    /// The default is [`transaction::Version::TWO`].
    pub fn transaction_version(mut self, version: transaction::Version) -> Self {
        self.0.tx_version = version;
        self
    }

    /// Builds a [`Constructor`] that can add inputs and outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::v2::{Creator, Constructor, Modifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .outputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<Modifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<Modifiable>::default();
    /// ```
    pub fn constructor_modifiable(self) -> Constructor<Modifiable> {
        let mut psbt = self.0;
        psbt.set_inputs_modifiable_flag();
        psbt.set_outputs_modifiable_flag();
        Constructor::<Modifiable>::from_psbt_unchecked(psbt)
    }

    /// Builds a [`Constructor`] that can only add inputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::v2::{Creator, Constructor, InputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<InputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_inputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<InputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_inputs_only_modifiable(self) -> Constructor<InputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.set_inputs_modifiable_flag();
        psbt.clear_outputs_modifiable_flag();
        Constructor::<InputsOnlyModifiable>::from_psbt_unchecked(psbt)
    }

    /// Builds a [`Constructor`] that can only add outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::v2::{Creator, Constructor, OutputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_outputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_outputs_only_modifiable(self) -> Constructor<OutputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.clear_inputs_modifiable_flag();
        psbt.set_outputs_modifiable_flag();
        Constructor::<OutputsOnlyModifiable>::from_psbt_unchecked(psbt)
    }

    /// Returns the created [`Psbt`].
    ///
    /// This is only required if the Creator and Constructor are separate entities. If the Creator
    /// is also acting as the Constructor use one of the `Self::constructor_foo` functions.
    pub fn psbt(self) -> Psbt {
        self.0
    }
}

impl Default for Creator {
    fn default() -> Self {
        Self::new()
    }
}
