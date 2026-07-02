// Taken from https://sourceforge.net/p/strobe (MIT Licence)
/**
 * @file x25519.h
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.
 *   Released under the MIT License. See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief X25519 key exchange and signatures.
 */

#ifndef __X25519_H__
#define __X25519_H__

#define X25519_BYTES (256 / 8)

/* The base point (9) */
extern const unsigned char X25519_BASE_POINT[X25519_BYTES];

/** Number of bytes in an EC public key */
#define EC_PUBLIC_BYTES 32

/** Number of bytes in an EC private key */
#define EC_PRIVATE_BYTES 32

/**
 * Number of bytes in a Schnorr challenge.
 * Could be set to 16 in a pinch. (FUTURE?)
 */
#define EC_CHALLENGE_BYTES 32

/** Enough bytes to get a uniform sample mod #E. For eg a Brainpool
 * curve this would need to be more than for a private key, but due
 * to the special prime used by Curve25519, the same size is enough.
 */
#define EC_UNIFORM_BYTES 32

/* x25519 scalar multiplication. Sets out to scalar*base.
 *
 * If clamp is set then the scalar will be clamped like a Curve25519 secret key.
 *
 * Per RFC 7748, this function returns failure (-1) if the output is zero and
 * clamp is set.
 */
int x25519(
    unsigned char out[EC_PUBLIC_BYTES],
    const unsigned char scalar[EC_PRIVATE_BYTES],
    const unsigned char base[EC_PUBLIC_BYTES],
    int clamp
);

static inline int x25519_base(
    unsigned char out[EC_PUBLIC_BYTES],
    const unsigned char scalar[EC_PRIVATE_BYTES],
    int clamp
) {
    return x25519(out, scalar, X25519_BASE_POINT, clamp);
}

static inline void x25519_base_uniform(
    unsigned char out[EC_PUBLIC_BYTES],
    const unsigned char scalar[EC_UNIFORM_BYTES]
) {
    (void) x25519_base(out, scalar, 0);
}

void x25519_sign_p2(
    unsigned char response[EC_PRIVATE_BYTES],
    const unsigned char challenge[EC_CHALLENGE_BYTES],
    const unsigned char eph_secret[EC_UNIFORM_BYTES],
    const unsigned char secret[EC_PRIVATE_BYTES]
);

int x25519_verify_p2(
    const unsigned char response[X25519_BYTES],
    const unsigned char challenge[X25519_BYTES],
    const unsigned char eph[X25519_BYTES],
    const unsigned char pub[X25519_BYTES]
);

#endif /* __X25519_H__ */
