// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Linq;
using System.Security.Cryptography;

namespace LuducatBridge
{
    /// <summary>
    /// Cryptographic helpers for the bridge protocol.
    /// Provides HKDF, TOTP, key generation, and verification code derivation.
    ///
    /// HKDF is manually implemented since .NET Framework 4.6.2 doesn't
    /// include System.Security.Cryptography.HKDF.
    /// </summary>
    public static class CryptoHelper
    {
        private const int TOTP_PERIOD = 30;
        private const int TOTP_WINDOW = 1;

        // ── HKDF (RFC 5869) ─────────────────────────────────────────

        /// <summary>
        /// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        /// </summary>
        public static byte[] HkdfExtract(byte[] salt, byte[] ikm)
        {
            using (var hmac = new HMACSHA256(salt))
            {
                return hmac.ComputeHash(ikm);
            }
        }

        /// <summary>
        /// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to length
        /// </summary>
        public static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
        {
            int hashLen = 32; // SHA-256
            int n = (int)Math.Ceiling((double)length / hashLen);
            byte[] okm = Array.Empty<byte>();
            byte[] t = Array.Empty<byte>();

            for (int i = 1; i <= n; i++)
            {
                byte[] input = new byte[t.Length + info.Length + 1];
                Array.Copy(t, 0, input, 0, t.Length);
                Array.Copy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = (byte)i;

                using (var hmac = new HMACSHA256(prk))
                {
                    t = hmac.ComputeHash(input);
                }

                byte[] newOkm = new byte[okm.Length + t.Length];
                Array.Copy(okm, 0, newOkm, 0, okm.Length);
                Array.Copy(t, 0, newOkm, okm.Length, t.Length);
                okm = newOkm;
            }

            byte[] result = new byte[length];
            Array.Copy(okm, result, length);
            return result;
        }

        /// <summary>
        /// HKDF-SHA256 key derivation (extract + expand).
        /// </summary>
        public static byte[] HkdfDeriveKey(byte[] ikm, int length, byte[] salt, byte[] info)
        {
            byte[] prk = HkdfExtract(salt, ikm);
            return HkdfExpand(prk, info, length);
        }

        // ── Verification Code ────────────────────────────────────────

        /// <summary>
        /// Derive 6-digit verification code from both public keys.
        /// Keys are sorted lexicographically before derivation.
        /// </summary>
        public static string DeriveVerificationCode(byte[] ourKey, byte[] peerKey)
        {
            return DeriveVerificationCode(ourKey, peerKey, null);
        }

        /// <summary>
        /// Derive 6-digit verification code from both public keys and
        /// optionally the server TLS certificate (DER bytes).
        /// Binding the cert hash into the IKM prevents MITM cert substitution.
        /// </summary>
        public static string DeriveVerificationCode(byte[] ourKey, byte[] peerKey, byte[] serverCertDer)
        {
            byte[][] sorted = new[] { ourKey, peerKey }
                .OrderBy(k => k, new ByteArrayComparer())
                .ToArray();

            byte[] ikm = Concat(sorted[0], sorted[1]);

            // Bind server certificate into IKM if available
            if (serverCertDer != null && serverCertDer.Length > 0)
            {
                byte[] certHash;
                using (var sha = SHA256.Create())
                {
                    certHash = sha.ComputeHash(serverCertDer);
                }
                ikm = Concat(ikm, certHash);
            }

            byte[] codeBytes = HkdfDeriveKey(ikm, 4, Protocol.VERIFY_SALT, Protocol.VERIFY_INFO);

            // Big-endian uint32
            if (BitConverter.IsLittleEndian)
                Array.Reverse(codeBytes);
            uint codeInt = BitConverter.ToUInt32(codeBytes, 0);

            return (codeInt % 1000000).ToString("D6");
        }

        /// <summary>
        /// Derive 20-byte TOTP shared secret from both public keys.
        /// </summary>
        public static byte[] DeriveTotpSecret(byte[] ourKey, byte[] peerKey)
        {
            byte[][] sorted = new[] { ourKey, peerKey }
                .OrderBy(k => k, new ByteArrayComparer())
                .ToArray();

            byte[] ikm = Concat(sorted[0], sorted[1]);

            return HkdfDeriveKey(ikm, 20, Protocol.TOTP_SALT, Protocol.TOTP_INFO);
        }

        // ── TOTP (RFC 6238) ─────────────────────────────────────────

        /// <summary>
        /// Compute a 6-digit TOTP value.
        /// </summary>
        public static string ComputeTotp(byte[] secret, int windowOffset = 0)
        {
            long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TOTP_PERIOD + windowOffset;
            byte[] counterBytes = BitConverter.GetBytes(counter);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(counterBytes);

            using (var hmac = new HMACSHA1(secret))
            {
                byte[] hash = hmac.ComputeHash(counterBytes);

                int offset = hash[hash.Length - 1] & 0x0F;
                int code = (hash[offset] & 0x7F) << 24
                         | hash[offset + 1] << 16
                         | hash[offset + 2] << 8
                         | hash[offset + 3];

                return (code % 1000000).ToString("D6");
            }
        }

        /// <summary>
        /// Verify a TOTP value with ±1 window tolerance.
        /// </summary>
        public static bool VerifyTotp(byte[] secret, string totpValue)
        {
            for (int window = -TOTP_WINDOW; window <= TOTP_WINDOW; window++)
            {
                if (string.Equals(ComputeTotp(secret, window), totpValue, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        // ── Key Generation (ECDSA P-256 via CNG) ─────────────────────

        // CNG blob layout for ECDSA P-256:
        //   EccPublicBlob:  Magic(4) + KeyLen(4) + X(32) + Y(32) = 72 bytes
        //   EccPrivateBlob: Magic(4) + KeyLen(4) + X(32) + Y(32) + D(32) = 104 bytes
        // Magic: public = 0x31534345 ("ECS1"), private = 0x32534345 ("ECS2")
        private const int CNG_HEADER_SIZE = 8;
        private const int P256_KEY_SIZE = 32;

        /// <summary>
        /// Generate an ECDSA P-256 key pair for signing challenges.
        /// Public key exported as uncompressed point (65 bytes: 0x04 || X || Y).
        /// CNG private blob stored for later signing.
        /// </summary>
        public static KeyPair GenerateKeyPair()
        {
            using (var key = CngKey.Create(CngAlgorithm.ECDsaP256))
            using (var ecdsa = new ECDsaCng(key))
            {
                byte[] privateBlob = key.Export(CngKeyBlobFormat.EccPrivateBlob);

                // Extract X, Y from CNG blob (skip 8-byte header)
                byte[] publicKey = new byte[65];
                publicKey[0] = 0x04;
                Array.Copy(privateBlob, CNG_HEADER_SIZE, publicKey, 1, P256_KEY_SIZE);
                Array.Copy(privateBlob, CNG_HEADER_SIZE + P256_KEY_SIZE, publicKey, 33, P256_KEY_SIZE);

                // D parameter (32 bytes after X and Y)
                byte[] privateKey = new byte[P256_KEY_SIZE];
                Array.Copy(privateBlob, CNG_HEADER_SIZE + P256_KEY_SIZE * 2, privateKey, 0, P256_KEY_SIZE);

                return new KeyPair(publicKey, privateKey, privateBlob);
            }
        }

        // ── Signing / Verification ────────────────────────────────────

        /// <summary>
        /// Sign data with our ECDSA P-256 private key (CNG private blob).
        /// Returns the DER-encoded signature.
        /// </summary>
        public static byte[] Sign(byte[] cngPrivateBlob, byte[] data)
        {
            using (var key = CngKey.Import(cngPrivateBlob, CngKeyBlobFormat.EccPrivateBlob))
            using (var ecdsa = new ECDsaCng(key))
            {
                ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                return ecdsa.SignData(data);
            }
        }

        /// <summary>
        /// Verify an ECDSA P-256 signature against a public key
        /// given as uncompressed point (65 bytes).
        /// </summary>
        public static bool Verify(byte[] publicKeyBytes, byte[] data, byte[] signature)
        {
            if (publicKeyBytes == null || publicKeyBytes.Length != 65 || publicKeyBytes[0] != 0x04)
                return false;

            // Build CNG EccPublicBlob: header + X + Y
            byte[] publicBlob = new byte[CNG_HEADER_SIZE + P256_KEY_SIZE * 2];
            // Magic: ECS1 = 0x31534345
            publicBlob[0] = 0x45; publicBlob[1] = 0x43; publicBlob[2] = 0x53; publicBlob[3] = 0x31;
            // Key length: 32
            publicBlob[4] = 0x20; publicBlob[5] = 0x00; publicBlob[6] = 0x00; publicBlob[7] = 0x00;
            Array.Copy(publicKeyBytes, 1, publicBlob, CNG_HEADER_SIZE, P256_KEY_SIZE);
            Array.Copy(publicKeyBytes, 33, publicBlob, CNG_HEADER_SIZE + P256_KEY_SIZE, P256_KEY_SIZE);

            using (var key = CngKey.Import(publicBlob, CngKeyBlobFormat.EccPublicBlob))
            using (var ecdsa = new ECDsaCng(key))
            {
                ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                return ecdsa.VerifyData(data, signature);
            }
        }

        /// <summary>
        /// Compute SHA-256 fingerprint of a public key.
        /// </summary>
        public static string ComputeFingerprint(byte[] publicKey)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(publicKey);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        /// <summary>
        /// Generate 32 random bytes for a challenge.
        /// </summary>
        public static byte[] GenerateChallenge()
        {
            byte[] challenge = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(challenge);
            }
            return challenge;
        }

        // ── Helpers ──────────────────────────────────────────────────

        internal static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }

    /// <summary>
    /// ECDSA P-256 key pair. Stores uncompressed public point and CNG private blob.
    /// </summary>
    public class KeyPair
    {
        public byte[] PublicKey { get; }
        public byte[] PrivateKey { get; }
        public byte[] CngPrivateBlob { get; }

        public KeyPair(byte[] publicKey, byte[] privateKey, byte[] cngPrivateBlob)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            CngPrivateBlob = cngPrivateBlob;
        }
    }

    /// <summary>Lexicographic byte array comparison for key sorting.</summary>
    internal class ByteArrayComparer : System.Collections.Generic.IComparer<byte[]>
    {
        public int Compare(byte[] x, byte[] y)
        {
            if (x == null && y == null) return 0;
            if (x == null) return -1;
            if (y == null) return 1;

            int minLen = Math.Min(x.Length, y.Length);
            for (int i = 0; i < minLen; i++)
            {
                int cmp = x[i].CompareTo(y[i]);
                if (cmp != 0) return cmp;
            }
            return x.Length.CompareTo(y.Length);
        }
    }
}
