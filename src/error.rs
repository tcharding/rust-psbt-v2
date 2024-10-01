// SPDX-License-Identifier: CC0-1.0

//! PSBT errors.

use core::fmt;

use bitcoin_internals::write_err;

/// Unable to determine lock time, multiple inputs have conflicting locking requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DetermineLockTimeError;

impl fmt::Display for DetermineLockTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unable to determine lock time, multiple inputs have conflicting locking requirements",
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DetermineLockTimeError {}

/// Error when passing an un-modifiable PSBT to a `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsbtNotModifiableError {
    /// The outputs modifiable flag is not set.
    Outputs(OutputsNotModifiableError),
    /// The inputs modifiable flag is not set.
    Inputs(InputsNotModifiableError),
}

impl fmt::Display for PsbtNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PsbtNotModifiableError::*;

        match *self {
            Outputs(ref e) => write_err!(f, "outputs not modifiable"; e),
            Inputs(ref e) => write_err!(f, "inputs not modifiable"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PsbtNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PsbtNotModifiableError::*;

        match *self {
            Outputs(ref e) => Some(e),
            Inputs(ref e) => Some(e),
        }
    }
}

impl From<InputsNotModifiableError> for PsbtNotModifiableError {
    fn from(e: InputsNotModifiableError) -> Self { Self::Inputs(e) }
}

impl From<OutputsNotModifiableError> for PsbtNotModifiableError {
    fn from(e: OutputsNotModifiableError) -> Self { Self::Outputs(e) }
}

/// Error when passing an PSBT with inputs not modifiable to an input adding `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InputsNotModifiableError;

impl fmt::Display for InputsNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSBT does not have the inputs modifiable flag set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsNotModifiableError {}

/// Error when passing an PSBT with outputs not modifiable to an output adding `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutputsNotModifiableError;

impl fmt::Display for OutputsNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSBT does not have the outputs modifiable flag set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputsNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// An error getting the funding transaction for this input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FundingUtxoError {
    /// The vout is out of bounds for non-witness transaction.
    OutOfBounds {
        /// The vout used as list index.
        vout: usize,
        /// The length of the utxo list.
        len: usize,
    },
    /// No funding utxo found.
    MissingUtxo,
}

impl fmt::Display for FundingUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FundingUtxoError::*;

        match *self {
            OutOfBounds { vout, len } => write!(f, "vout {} out of bounds for tx list len: {}", vout, len),
            MissingUtxo => write!(f, "no funding utxo found"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FundingUtxoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FundingUtxoError::*;

        match *self {
            OutOfBounds { .. } | MissingUtxo => None,
        }
    }
}
