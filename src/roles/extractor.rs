// SPDX-License-Identifier: CC0-1.0

//! Implementation of the Extractor role as defined in [BIP-174].
//!
//! # Extractor Role
//!
//! > The Transaction Extractor does not need to know how to interpret scripts in order
//! > to extract the network serialized transaction.
//!
//! It is only possible to extract a transaction from a PSBT _after_ it has been finalized. However
//! the Extractor role may be fulfilled by a separate entity to the Finalizer hence this is a
//! separate module and does not require the "miniscript" feature be enabled.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use core::fmt;

use bitcoin::psbt::ExtractTxFeeRateError;
use bitcoin::{FeeRate, Transaction, Txid};

use crate::error::{write_err, FeeError};
use crate::{DetermineLockTimeError, Psbt};

/// Implements the BIP-370 Finalized role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Extractor(Psbt);

// TODO: Check the BIP to see if current rust-bitcoin code makes sense when combined with this
// crates Finalizer role. Also check if we can do it better if we don't use `to_psbt_v0`.
impl Extractor {
    /// Creates an `Extractor`.
    ///
    /// An extractor can only accept a PSBT that has been finalized.
    pub fn new(psbt: Psbt) -> Result<Self, ExtractError> {
        if psbt.inputs.iter().any(|input| !input.is_finalized()) {
            return Err(ExtractError::PsbtNotFinalized);
        }
        let _ = psbt.determine_lock_time()?;

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Extractor guarantees lock time can be determined")
    }

    /// An alias for [`Self::extract_tx_fee_rate_limit`].
    pub fn extract_tx(&self) -> Result<Transaction, ExtractTxFeeRateError> { self.to_psbt_v0().extract_tx() }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// `ExtractTxError` variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    pub fn extract_tx_fee_rate_limit(&self) -> Result<Transaction, ExtractTxFeeRateError> {
        self.to_psbt_v0().extract_tx_fee_rate_limit()
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    pub fn extract_tx_with_fee_rate_limit(
        &self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxFeeRateError> {
        self.to_psbt_v0().extract_tx_fee_with_rate_limit(max_fee_rate)
    }

    /// Perform [`Self::extract_tx_fee_rate_limit`] without the fee rate check.
    ///
    /// This can result in a transaction with absurdly high fees. Use with caution.
    pub fn extract_tx_unchecked_fee_rate(&self) -> Result<Transaction, ExtractTxError> {
        self.to_psbt_v0().extract_tx_unchecked_rate_limit()
    }
}

/// Error constructing an `Extractor`.
#[derive(Debug)]
pub enum ExtractError {
    /// Attempted to extract tx from an unfinalized PSBT.
    PsbtNotFinalized,
    /// Finalizer must be able to determine the lock time.
    DetermineLockTime(DetermineLockTimeError),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractError::*;

        match *self {
            PsbtNotFinalized => write!(f, "attempted to extract tx from an unfinalized PSBT"),
            DetermineLockTime(ref e) =>
                write_err!(f, "extractor must be able to determine the lock time"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ExtractError::*;

        match *self {
            DetermineLockTime(ref e) => Some(e),
            PsbtNotFinalized => None,
        }
    }
}
