// SPDX-License-Identifier: CC0-1.0

//! The PSBT Version 2 Updater role.

use crate::error::DetermineLockTimeError;
use crate::Psbt;

/// Implements the BIP-370 Updater role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Updater(Psbt);

impl Updater {
    /// Creates an `Updater`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn from_psbt(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }
}

impl TryFrom<Psbt> for Updater {
    type Error = DetermineLockTimeError;

    fn try_from(psbt: Psbt) -> Result<Self, Self::Error> {
        Self::from_psbt(psbt)
    }
}
