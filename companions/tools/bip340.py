"""BIP-340 Schnorr (x-only keys), stdlib only. Sign is for TEST VECTORS; verify mirrors the Solidity verifier."""
import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt = _add(pt, pt); k >>= 1
    return r


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def lift_x(x):
    if x >= P: return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2: return None
    return (x, y if y % 2 == 0 else P - y)


def pubkey(sk):
    return mul(sk)[0].to_bytes(32, "big")


def sign(sk, msg, aux=bytes(32)):
    Pt = mul(sk); d = sk if Pt[1] % 2 == 0 else N - sk
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + Pt[0].to_bytes(32, "big") + msg), "big") % N
    R = mul(k0); k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge", R[0].to_bytes(32, "big") + Pt[0].to_bytes(32, "big") + msg), "big") % N
    return R[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


def verify(px, msg, sig):
    Pt = lift_x(int.from_bytes(px, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if Pt is None or r >= P or s >= N: return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + px + msg), "big") % N
    R = _add(mul(s), mul(N - e, Pt))
    return R is not None and R[1] % 2 == 0 and R[0] == r
