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
            byte[] okm = new byte[0];
            byte[] t = new byte[0];

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
            byte[][] sorted = new[] { ourKey, peerKey }
                .OrderBy(k => k, new ByteArrayComparer())
                .ToArray();

            byte[] ikm = Concat(sorted[0], sorted[1]);

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
                if (ComputeTotp(secret, window) == totpValue)
                    return true;
            }
            return false;
        }

        // ── Key Generation ───────────────────────────────────────────

        /// <summary>
        /// Generate a 32-byte random key pair.
        /// Note: This is a simplified key generation for the protocol.
        /// In production with .NET 9+, use proper Ed25519.
        /// </summary>
        public static KeyPair GenerateKeyPair()
        {
            byte[] seed = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(seed);
            }
            // Derive public key from seed via SHA-256
            // (simplified — real Ed25519 uses curve math)
            byte[] publicKey;
            using (var sha = SHA256.Create())
            {
                publicKey = sha.ComputeHash(seed);
            }
            return new KeyPair(publicKey, seed);
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

        // ── Helpers ──────────────────────────────────────────────────

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }

    public class KeyPair
    {
        public byte[] PublicKey { get; }
        public byte[] PrivateKey { get; }

        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
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
