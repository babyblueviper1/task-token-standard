// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

// EXPERIMENTAL — companion code, not part of the ERC's reference implementation.

/// @title  BIP-340 Schnorr verification over secp256k1 (x-only public keys)
/// @notice verify(px, m, rx, s) is true iff (rx || s) is a valid BIP-340 signature by the x-only key px over the
///         32-byte message m. It computes R = s·G − e·P with one ecrecover call and checks that R has x = rx and
///         an even y, as BIP-340 requires.
/// @dev    The ecrecover identity. ecrecover(h, v, r, s') returns the address of r⁻¹·(s'·R0 − h·G), where R0 is the
///         point with x = r and y parity v − 27. With r = px, v = 27 (P has even y by the x-only convention),
///         s' = −e·px and h = −s·px (mod n), that point is px⁻¹·(−e·px·P + s·px·G) = s·G − e·P = R.
///         The expected R is lift_x(rx) with its even root, computed with the modexp precompile. Comparing
///         addresses compares points: R and the expected point share an address only if they are equal, up to a
///         keccak collision on 160 bits.
///         Inputs outside the ecrecover domain are rejected rather than handled: px must be below n (ecrecover's r),
///         which excludes x-only keys in [n, p), a set of probability about 2⁻¹²⁸. A signature whose recomputed e·px is
///         0 mod n is also rejected (the precompile refuses s' = 0). A recomputed s·px that is 0 mod n is accepted
///         as input and mapped to h = 0: the recovered point is then −e·P, which must still equal lift_x(rx) with an
///         even y, so it cannot make an invalid signature verify. Both happen with negligible probability for an
///         honest key.
library Bip340 {
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 internal constant CHALLENGE_TAG = sha256("BIP0340/challenge");

    function verify(bytes32 px, bytes32 m, bytes32 rx, bytes32 s) internal view returns (bool) {
        uint256 x = uint256(px);
        uint256 r = uint256(rx);
        uint256 sv = uint256(s);
        // sv >= N is BIP-340's rule. Without it a forgery would need a valid s below 2^256 - n (about 2^128), which is
        // infeasible to produce, so no test vector can separate the two; it is kept because the spec requires it.
        if (x == 0 || x >= N || r >= P || sv >= N) return false;
        if (!_hasRoot(x)) return false; // lift_x(px) must exist (ecrecover also refuses an off-curve r; kept as the spec's own check)
        uint256 e = uint256(sha256(abi.encodePacked(CHALLENGE_TAG, CHALLENGE_TAG, rx, px, m))) % N;
        uint256 sx = mulmod(sv, x, N);
        uint256 ex = mulmod(e, x, N);
        if (ex == 0) return false;
        address got = ecrecover(bytes32(sx == 0 ? 0 : N - sx), 27, px, bytes32(N - ex));
        if (got == address(0)) return false;
        (bool ok, uint256 y) = _evenRoot(r);
        if (!ok) return false;
        return got == address(uint160(uint256(keccak256(abi.encodePacked(r, y)))));
    }

    /// @notice true iff px can verify anything: nonzero, below n (ecrecover's domain) and lifts to a curve point.
    function isValidKey(bytes32 px) internal view returns (bool) {
        uint256 x = uint256(px);
        return x != 0 && x < N && _hasRoot(x);
    }

    function _hasRoot(uint256 x) private view returns (bool ok) {
        (ok,) = _evenRoot(x);
    }

    /// @dev y with y² = x³ + 7 (mod p) and y even, if x is on the curve.
    function _evenRoot(uint256 x) private view returns (bool, uint256) {
        uint256 c = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        uint256 y = _modexp(c, (P + 1) / 4);
        if (mulmod(y, y, P) != c) return (false, 0);
        return (true, y & 1 == 0 ? y : P - y);
    }

    function _modexp(uint256 b, uint256 ex) private view returns (uint256 out) {
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), b, ex, P);
        (bool ok, bytes memory ret) = address(0x05).staticcall(input);
        require(ok && ret.length == 32, "modexp");
        out = abi.decode(ret, (uint256));
    }
}
