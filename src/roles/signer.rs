// SPDX-License-Identifier: CC0-1.0

//! The PSBT Version 2 Updater role.

use crate::error::DetermineLockTimeError;
use crate::Psbt;

/// Implements the BIP-370 Signer role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signer(Psbt);

impl Signer {
    /// Creates a `Signer`.
    ///
    /// A signer can only sign a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid { self.0.id().expect("Signer guarantees lock time can be determined") }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    pub fn unsigned_tx(&self) -> Transaction {
        self.0.unsigned_tx().expect("Signer guarantees lock time can be determined")
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<(Psbt, SigningKeys), (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let tx = self.unsigned_tx();
        let mut psbt = self.psbt();

        psbt.sign(tx, k, secp).map(|signing_keys| (psbt, signing_keys))
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing an ECDSA input.
    ///
    /// > For PSBTv2s, a signer must update the PSBT_GLOBAL_TX_MODIFIABLE field after signing
    /// > inputs so that it accurately reflects the state of the PSBT.
    pub fn ecdsa_clear_tx_modifiable(&mut self, ty: EcdsaSighashType) {
        self.0.clear_tx_modifiable(ty as u8)
    }

    /// Returns the inner [`Psbt`].
    pub fn into_inner(self) -> Psbt { self.0 }
}
