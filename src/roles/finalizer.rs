// SPDX-License-Identifier: CC0-1.0

//! The PSBT Version 2 Finalizer role.

use miniscript::psbt::{FinalizeError, PsbtExt};

use crate::error::DetermineLockTimeError;
use crate::Psbt;

/// Implements the BIP-370 Finalizer role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Finalizer(Psbt);

impl Finalizer {
    /// Creates an `Finalizer`.
    ///
    /// A finalizer can only be created if all inputs have a funding UTXO.
    pub fn new(psbt: Psbt) -> Result<Self, Error> {
        psbt.inptus.iter().all(|input| input.funding_utxo())?;
        let _ = psbt.determine_lock_time()?;
        psbt.check_partial_sigs_sighash_type()?;

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Finalizer guarantees lock time can be determined")
    }

    /// Finalize the PSBT using `rust-miniscript`.
    pub fn finalize<C: Verification>(self, secp: &Secp256k1<C>) -> Result<bitcoin::psbt::Psbt, FinalizeError> {
        self.0.finalize(secp)
    }

    /// Checks the sighash types of input partial sigs (ECDSA).
    fn check_partial_sigs_sighash_type(
        &self,
    ) -> Result<(), PartialSigsSighashTypeError> {
        use PartialSigsSighashTypeError::*;

        for (input_index, input) in self.inputs.iter().enumerate() {
            let target_ecdsa_sighash_ty = match input.sighash_type {
                Some(psbt_hash_ty) => psbt_hash_ty
                    .ecdsa_hash_ty()
                    .map_err(|error| NonStandardInputSighashType { input_index, error })?,
                None => EcdsaSighashType::All,
            };

            for (key, ecdsa_sig) in &input.partial_sigs {
                let flag = EcdsaSighashType::from_standard(ecdsa_sig.sighash_type as u32)
                    .map_err(|error| NonStandardPartialSigsSighashType { input_index, error })?;
                if target_ecdsa_sighash_ty != flag {
                    return Err(WrongSighashFlag {
                        input_index,
                        required: target_ecdsa_sighash_ty,
                        got: flag,
                        pubkey: *key,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Error constructing a [`Finalizer`].
#[derive(Debug)]
pub enum Error {
    /// An input is missing its funding UTXO.
    FundingUtxo(FundingUtxoError),
    /// Finalizer must be able to determine the lock time.
    DetermineLockTime(DetermineLockTimeError),
    /// An input has incorrect sighash type for its partial sigs (ECDSA).
    PartialSigsSighashType(PartialSigsSighashTypeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match *self {
            // TODO: Loads of error messages are capitalized, they should not be.
            FundingUtxo(ref e) => write_err!(f, "Finalizer missing funding UTXO"; e),
            DetermineLockTime(ref e) =>
                write_err!(f, "finalizer must be able to determine the lock time"; e),
            PartialSigsSighashType(ref e) => write_err!(f, "Finalizer sighash type error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            FundingUtxo(ref e) => Some(e),
            DetermineLockTime(ref e) => Some(e),
            PartialSigsSighashType(ref e) => Some(e),
        }
    }
}

impl From<FundingUtxoError> for Error {
    fn from(e: FundingUtxoError) -> Self { Self::FundingUtxo(e) }
}

impl From<DetermineLockTimeError> for Error {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

impl From<PartialSigsSighashTypeError> for Error {
    fn from(e: PartialSigsSighashTypeError) -> Self { Self::PartialSigsSighashType(e) }
}

// TODO: Consider creating a type that has input_index and E and simplify all these similar error types?
/// Error checking the partials sigs have correct sighash types.
#[derive(Debug)]
pub enum PartialSigsSighashTypeError {
    /// Non-standard sighash type found in `input.sighash_type` field.
    NonStandardInputSighashType {
        /// The input index with the non-standard sighash type.
        input_index: usize,
        /// The non-standard sighash type error.
        error: NonStandardSighashTypeError,
    },
    /// Non-standard sighash type found in `input.partial_sigs`.
    NonStandardPartialSigsSighashType {
        /// The input index with the non-standard sighash type.
        input_index: usize,
        /// The non-standard sighash type error.
        error: NonStandardSighashTypeError,
    },
    /// Wrong sighash flag in partial signature.
    WrongSighashFlag {
        /// The input index with the wrong sighash flag.
        input_index: usize,
        /// The sighash type we got.
        got: EcdsaSighashType,
        /// The sighash type we require.
        required: EcdsaSighashType,
        /// The associated pubkey (key into the `input.partial_sigs` map).
        pubkey: PublicKey,
    },
}

impl fmt::Display for PartialSigsSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PartialSigsSighashTypeError::*;

        match *self {
            NonStandardInputSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in sighash_type field", input_index; error),
            NonStandardPartialSigsSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in partial_sigs", input_index; error),
            WrongSighashFlag { input_index, got, required, pubkey } => write!(
                f,
                "wrong sighash flag for input {} (got: {}, required: {}) pubkey: {}",
                input_index, got, required, pubkey
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PartialSigsSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PartialSigsSighashTypeError::*;

        // TODO: Is this correct for a struct error fields?
        match *self {
            NonStandardInputSighashType { input_index: _, ref error } => Some(error),
            NonStandardPartialSigsSighashType { input_index: _, ref error } => Some(error),
            WrongSighashFlag { .. } => None,
        }
    }
}
