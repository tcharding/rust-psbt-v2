// SPDX-License-Identifier: CC0-1.0

//! The PSBT Version 2 Signer role.

use crate::error::DetermineLockTimeError;
use crate::Psbt;

/// Implements the BIP-370 Updater role.
///
/// The inner [`Psbt`] field is public to make explicit that the updater role requires manually
/// setting fields within the PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Updater(pub Psbt);

// FIXME: Currently this is not adding much value, can we do better?
impl Updater {
    /// Creates an `Updater`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn from_psbt(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Updater guarantees lock time can be determined")
    }

    /// Updater role, update the sequence number for input at `index`.
    pub fn set_sequence(
        mut self,
        n: Sequence,
        input_index: usize,
    ) -> Result<Updater, IndexOutOfBoundsError> {
        let input = self.0.checked_input_mut(input_index)?;
        input.sequence = Some(n);
        Ok(self)
    }

    /// Returns the inner [`Psbt`].
    pub fn into_inner(self) -> Psbt { self.0 }
}

impl TryFrom<Psbt> for Updater {
    type Error = DetermineLockTimeError;

    fn try_from(psbt: Psbt) -> Result<Self, Self::Error> { Self::new(psbt) }
}
