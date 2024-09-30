// SPDX-License-Identifier: CC0-1.0

//! PSBT Version 2 roles.
//!
//! BIP-370 describes various roles, these are implemented in this module as follows:
//!
//! - The **Creator** role: Use the [`Creator`] type - or if creator and constructor are a single entity just use the `Constructor`.
//! - The **Constructor**: Use the [`Constructor`] type.
//! - The **Updater** role: Use the [`Updater`] type and then update additional fields of the [`Psbt`] directly.
//! - The **Signer** role: Use the [`Signer`] type.
//! - The **Finalizer** role: Use the `Finalizer` type (requires "miniscript" feature).
//! - The **Extractor** role: Use the [`Extractor`] type.
//!
//! To combine PSBTs use either `psbt.combine_with(other)` or `v2::combine(this, that)`.

mod constructor;
mod creator;
mod updater;

#[allow(unused_imports)] // TODO: Clear this.
pub use self::{constructor::Constructor, creator::Creator, updater::Updater};
