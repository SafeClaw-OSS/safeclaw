//! P-256 public key reconstruction from x/y coordinates.
//!
//! Used by `passkey::webauthn` to verify ECDSA assertions against the
//! credential's stored public key.

use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};

use crate::error::{AppError, Result};

/// Reconstruct a P-256 public key from raw x and y coordinate bytes.
///
/// Each coordinate must be exactly 32 bytes.
pub fn public_key_from_xy(x: &[u8], y: &[u8]) -> Result<PublicKey> {
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::Unauthorized(
            "passkey x/y must be 32 bytes each".into(),
        ));
    }
    let mut x_arr = [0u8; 32];
    x_arr.copy_from_slice(x);
    let mut y_arr = [0u8; 32];
    y_arr.copy_from_slice(y);

    let point = EncodedPoint::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
    let pk_opt: Option<PublicKey> = PublicKey::from_encoded_point(&point).into();
    pk_opt.ok_or_else(|| AppError::Unauthorized("invalid passkey point".into()))
}
