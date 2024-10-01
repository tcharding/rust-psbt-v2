// SPDX-License-Identifier: CC0-1.0

//! The PSBT Version 2 Constructor role.

use core::marker::PhantomData;

use crate::error::{
    DetermineLockTimeError, InputsNotModifiableError, OutputsNotModifiableError,
    PsbtNotModifiableError,
};
use crate::roles::creator::Creator;
use crate::roles::updater::Updater;
use crate::{Input, Output, Psbt};

/// Implements the BIP-370 Constructor role.
///
/// Uses the builder pattern, and generics to make adding inputs and outputs infallible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Constructor<T>(Psbt, PhantomData<T>);

impl<T: Mod> Constructor<T> {
    /// Returns a PSBT [`Updater`] once construction is completed.
    pub fn updater(self) -> Result<Updater, DetermineLockTimeError> {
        Updater::from_psbt(self.no_more_inputs().no_more_outputs().psbt()?)
    }

    /// Marks that the `Psbt` can not have any more inputs added to it.
    pub fn no_more_inputs(mut self) -> Self {
        self.0.clear_inputs_modifiable_flag();
        self
    }

    /// Marks that the `Psbt` can not have any more outputs added to it.
    pub fn no_more_outputs(mut self) -> Self {
        self.0.clear_outputs_modifiable_flag();
        self
    }

    /// Returns the inner [`Psbt`] in its current state.
    ///
    /// This function can be used either to get the [`Psbt`] to pass to another constructor or to
    /// get the [`Psbt`] ready for update if `no_more_inputs` and `no_more_outputs` have already
    /// explicitly been called.
    pub fn into_inner(self) -> Result<Psbt, DetermineLockTimeError> {
        let _ = self.0.determine_lock_time()?;
        Ok(self.0)
    }
}

impl Constructor<Modifiable> {
    /// Creates a new PSBT Creator with an empty `Psbt`.
    pub fn new() -> Self { Creator::new().constructor_modifiable() }

    /// Creates a new Constructor from an already created `Psbt`.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// (e.g. `constructor_modifiable()`) or create a empty Constructor (`Constructor::new()`).
    pub fn from_psbt(psbt: Psbt) -> Result<Self, PsbtNotModifiableError> {
        if !psbt.is_inputs_modifiable() {
            Err(InputsNotModifiableError.into())
        } else if !psbt.is_outputs_modifiable() {
            Err(OutputsNotModifiableError.into())
        } else {
            Ok(Self(psbt, PhantomData))
        }
    }

    pub(crate) fn from_psbt_unchecked(psbt: Psbt) -> Self { Self(psbt, PhantomData) }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.input_count += 1;
        self
    }

    /// Adds an output to the PSBT.
    pub fn output(mut self, output: Output) -> Self {
        self.0.outputs.push(output);
        self.0.output_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<Modifiable> {
    fn default() -> Self { Self::new() }
}

impl Constructor<InputsOnlyModifiable> {
    /// Creates a new PSBT Creator with an empty `Psbt`.
    pub fn new() -> Self { Creator::new().constructor_inputs_only_modifiable() }

    /// Creates a new Constructor from an already created `Psbt`.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn from_psbt(psbt: Psbt) -> Result<Self, InputsNotModifiableError> {
        if psbt.is_inputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(InputsNotModifiableError)
        }
    }

    pub(crate) fn from_psbt_unchecked(psbt: Psbt) -> Self { Self(psbt, PhantomData) }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.input_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<InputsOnlyModifiable> {
    fn default() -> Self { Self::new() }
}

impl Constructor<OutputsOnlyModifiable> {
    /// Creates a new PSBT Creator with an empty `Psbt`.
    pub fn new() -> Self { Creator::new().constructor_outputs_only_modifiable() }

    /// Creates a new Constructor from an already created `Psbt`.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn from_psbt(psbt: Psbt) -> Result<Self, OutputsNotModifiableError> {
        if psbt.is_outputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(OutputsNotModifiableError)
        }
    }

    pub(crate) fn from_psbt_unchecked(psbt: Psbt) -> Self { Self(psbt, PhantomData) }

    /// Adds an output to the PSBT.
    pub fn output(mut self, output: Output) -> Self {
        self.0.outputs.push(output);
        self.0.output_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<OutputsOnlyModifiable> {
    fn default() -> Self { Self::new() }
}

/// Marker for a `Constructor` with both inputs and outputs modifiable.
pub enum Modifiable {}

/// Marker for a `Constructor` with inputs modifiable.
pub enum InputsOnlyModifiable {}

/// Marker for a `Constructor` with outputs modifiable.
pub enum OutputsOnlyModifiable {}

mod sealed {
    pub trait Mod {}
    impl Mod for super::Modifiable {}
    impl Mod for super::InputsOnlyModifiable {}
    impl Mod for super::OutputsOnlyModifiable {}
}

/// Marker for if either inputs or outputs are modifiable, or both.
pub trait Mod: sealed::Mod + Sync + Send + Sized + Unpin {}

impl Mod for Modifiable {}
impl Mod for InputsOnlyModifiable {}
impl Mod for OutputsOnlyModifiable {}
