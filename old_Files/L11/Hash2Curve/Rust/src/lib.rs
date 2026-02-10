//! Generic hash-to-curve wrapper (compile-time selection).
//!
//! The caller selects:
//! - the curve type `C` (e.g., p256::NistP256, k256::Secp256k1), and
//! - the expander `X` (e.g., ExpandMsgXmd<sha2::Sha256>, ExpandMsgXmd<sha3::Sha3_256>,
//!   or ExpandMsgXof<sha3::Shake256>).

use elliptic_curve::hash2curve::{ExpandMsg, GroupDigest};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::CurveArithmetic;

#[derive(Debug)]
pub enum Hash2CurveError {
    CryptoError,
}

/// Generic hash-to-curve wrapper.
///
/// - `C` is the curve type (chosen at compile time).
/// - `X` is the expander (chosen at compile time), which determines the hash/XOF.
/// - `msg` is the input message to be hashed to the curve.
/// - `dst` is the domain separation tag (DST).
///
/// IMPORTANT: In real protocols, the suite (curve + expander + DST) is fixed by the spec.
pub fn hash2curve<C, X>(
    msg: &[u8],
    dst: &[u8],
) -> Result<<C as CurveArithmetic>::ProjectivePoint, Hash2CurveError>
where
    C: GroupDigest,
    // Repeat this bound explicitly (avoids the "CofactorGroup not satisfied" errors).
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    for<'a> X: ExpandMsg<'a>,
{
    C::hash_from_bytes::<X>(&[msg], &[dst]).map_err(|_| Hash2CurveError::CryptoError)
}

/// Demo wrapper with a fixed DST.
pub fn hash2curve_demo<C, X>(
    msg: &[u8],
) -> Result<<C as CurveArithmetic>::ProjectivePoint, Hash2CurveError>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    for<'a> X: ExpandMsg<'a>,
{
    const DST: &[u8] = b"CRYPTOGRAPHY_ENGINEERING-DEMO-HASH2CURVE-RUST";
    hash2curve::<C, X>(msg, DST)
}
