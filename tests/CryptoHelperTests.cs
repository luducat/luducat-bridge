// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Linq;
using Xunit;

namespace LuducatBridge.Tests
{
    public class CryptoHelperTests
    {
        // ── HKDF ──────────────────────────────────────────────────────

        [Fact]
        public void HkdfExtract_DeterministicOutput()
        {
            byte[] salt = new byte[] { 1, 2, 3 };
            byte[] ikm = new byte[] { 4, 5, 6 };

            byte[] result1 = CryptoHelper.HkdfExtract(salt, ikm);
            byte[] result2 = CryptoHelper.HkdfExtract(salt, ikm);

            Assert.Equal(32, result1.Length);
            Assert.Equal(result1, result2);
        }

        [Fact]
        public void HkdfExpand_ProducesRequestedLength()
        {
            byte[] prk = CryptoHelper.HkdfExtract(new byte[32], new byte[16]);
            byte[] info = new byte[] { 0x01 };

            byte[] out4 = CryptoHelper.HkdfExpand(prk, info, 4);
            byte[] out64 = CryptoHelper.HkdfExpand(prk, info, 64);

            Assert.Equal(4, out4.Length);
            Assert.Equal(64, out64.Length);
        }

        [Fact]
        public void HkdfDeriveKey_CombinesExtractAndExpand()
        {
            byte[] ikm = new byte[] { 10, 20, 30 };
            byte[] salt = new byte[] { 1, 2, 3 };
            byte[] info = new byte[] { 7, 8, 9 };

            byte[] result = CryptoHelper.HkdfDeriveKey(ikm, 20, salt, info);

            Assert.Equal(20, result.Length);
            // Deterministic
            Assert.Equal(result, CryptoHelper.HkdfDeriveKey(ikm, 20, salt, info));
        }

        // ── Verification Code ─────────────────────────────────────────

        [Fact]
        public void DeriveVerificationCode_Returns6Digits()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            key1[1] = 0xAA;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0xBB;

            string code = CryptoHelper.DeriveVerificationCode(key1, key2);

            Assert.Equal(6, code.Length);
            Assert.True(code.All(c => c >= '0' && c <= '9'));
        }

        [Fact]
        public void DeriveVerificationCode_Deterministic()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            for (int i = 1; i < 33; i++) key1[i] = (byte)i;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            for (int i = 1; i < 33; i++) key2[i] = (byte)(i + 100);

            string code1 = CryptoHelper.DeriveVerificationCode(key1, key2);
            string code2 = CryptoHelper.DeriveVerificationCode(key1, key2);

            Assert.Equal(code1, code2);
        }

        [Fact]
        public void DeriveVerificationCode_OrderIndependent()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            key1[1] = 0x11;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0x22;

            string codeAB = CryptoHelper.DeriveVerificationCode(key1, key2);
            string codeBA = CryptoHelper.DeriveVerificationCode(key2, key1);

            Assert.Equal(codeAB, codeBA);
        }

        [Fact]
        public void DeriveVerificationCode_CertBindingChangesCode()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            key1[1] = 0x55;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0x66;

            byte[] cert1 = new byte[] { 0x30, 0x82, 0x01 };
            byte[] cert2 = new byte[] { 0x30, 0x82, 0x02 };

            string codeNoCert = CryptoHelper.DeriveVerificationCode(key1, key2);
            string codeCert1 = CryptoHelper.DeriveVerificationCode(key1, key2, cert1);
            string codeCert2 = CryptoHelper.DeriveVerificationCode(key1, key2, cert2);

            // Different cert DER → different code
            Assert.NotEqual(codeCert1, codeCert2);
            // Cert binding changes code vs no cert
            Assert.NotEqual(codeNoCert, codeCert1);
        }

        [Fact]
        public void DeriveVerificationCode_TimestampChangesCode()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            key1[1] = 0x77;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0x88;

            string codeTs0 = CryptoHelper.DeriveVerificationCode(key1, key2, null, 0);
            string codeTs1 = CryptoHelper.DeriveVerificationCode(key1, key2, null, 100);
            string codeTs2 = CryptoHelper.DeriveVerificationCode(key1, key2, null, 200);

            Assert.NotEqual(codeTs1, codeTs2);
        }

        [Fact]
        public void DeriveVerificationCode_CertPlusTimestamp()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            key1[1] = 0xCC;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0xDD;
            byte[] cert = new byte[] { 0x30, 0x82, 0x03, 0x45 };

            string code1 = CryptoHelper.DeriveVerificationCode(key1, key2, cert, 42);
            string code2 = CryptoHelper.DeriveVerificationCode(key1, key2, cert, 42);
            string code3 = CryptoHelper.DeriveVerificationCode(key1, key2, cert, 43);

            Assert.Equal(code1, code2);
            Assert.NotEqual(code1, code3);
        }

        // ── TOTP ──────────────────────────────────────────────────────

        [Fact]
        public void DeriveTotpSecret_Returns20Bytes()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0x01;

            byte[] secret = CryptoHelper.DeriveTotpSecret(key1, key2);

            Assert.Equal(20, secret.Length);
        }

        [Fact]
        public void DeriveTotpSecret_OrderIndependent()
        {
            byte[] key1 = new byte[65];
            key1[0] = 0x04;
            key1[1] = 0xAA;
            byte[] key2 = new byte[65];
            key2[0] = 0x04;
            key2[1] = 0xBB;

            Assert.Equal(
                CryptoHelper.DeriveTotpSecret(key1, key2),
                CryptoHelper.DeriveTotpSecret(key2, key1));
        }

        [Fact]
        public void ComputeTotp_Returns6Digits()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 1);

            string totp = CryptoHelper.ComputeTotp(secret);

            Assert.Equal(6, totp.Length);
            Assert.True(totp.All(c => c >= '0' && c <= '9'));
        }

        [Fact]
        public void VerifyTotp_AcceptsCurrentWindow()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 42);

            string currentTotp = CryptoHelper.ComputeTotp(secret, 0);

            Assert.True(CryptoHelper.VerifyTotp(secret, currentTotp));
        }

        [Fact]
        public void VerifyTotp_AcceptsPreviousWindow()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 42);

            string prevTotp = CryptoHelper.ComputeTotp(secret, -1);

            Assert.True(CryptoHelper.VerifyTotp(secret, prevTotp));
        }

        [Fact]
        public void VerifyTotp_RejectsInvalidCode()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 42);

            Assert.False(CryptoHelper.VerifyTotp(secret, "000000"));
        }

        [Fact]
        public void VerifyTotp_RejectsEmptyCode()
        {
            byte[] secret = new byte[20];
            Assert.False(CryptoHelper.VerifyTotp(secret, ""));
        }

        // ── Key Generation ────────────────────────────────────────────

        [Fact]
        public void GenerateKeyPair_ProducesValidKeys()
        {
            var kp = CryptoHelper.GenerateKeyPair();

            Assert.NotNull(kp.PublicKey);
            Assert.NotNull(kp.PrivateKey);
            Assert.NotNull(kp.CngPrivateBlob);
            Assert.Equal(65, kp.PublicKey.Length);
            Assert.Equal(0x04, kp.PublicKey[0]);
            Assert.Equal(32, kp.PrivateKey.Length);
        }

        [Fact]
        public void GenerateKeyPair_ProducesDifferentKeys()
        {
            var kp1 = CryptoHelper.GenerateKeyPair();
            var kp2 = CryptoHelper.GenerateKeyPair();

            Assert.NotEqual(kp1.PublicKey, kp2.PublicKey);
            Assert.NotEqual(kp1.PrivateKey, kp2.PrivateKey);
        }

        // ── Signing ───────────────────────────────────────────────────

        [Fact]
        public void SignAndVerify_RoundTrip()
        {
            var kp = CryptoHelper.GenerateKeyPair();
            byte[] data = new byte[] { 1, 2, 3, 4, 5 };

            byte[] sig = CryptoHelper.Sign(kp.CngPrivateBlob, data);
            bool valid = CryptoHelper.Verify(kp.PublicKey, data, sig);

            Assert.True(valid);
        }

        [Fact]
        public void Verify_RejectsTamperedData()
        {
            var kp = CryptoHelper.GenerateKeyPair();
            byte[] data = new byte[] { 1, 2, 3, 4, 5 };
            byte[] sig = CryptoHelper.Sign(kp.CngPrivateBlob, data);

            byte[] tampered = new byte[] { 1, 2, 3, 4, 6 };

            Assert.False(CryptoHelper.Verify(kp.PublicKey, tampered, sig));
        }

        [Fact]
        public void Verify_RejectsWrongKey()
        {
            var kp1 = CryptoHelper.GenerateKeyPair();
            var kp2 = CryptoHelper.GenerateKeyPair();
            byte[] data = new byte[] { 10, 20, 30 };
            byte[] sig = CryptoHelper.Sign(kp1.CngPrivateBlob, data);

            Assert.False(CryptoHelper.Verify(kp2.PublicKey, data, sig));
        }

        [Fact]
        public void Verify_RejectsInvalidPublicKeyFormat()
        {
            byte[] badKey = new byte[] { 0x03, 0x01, 0x02 };
            byte[] data = new byte[] { 1, 2, 3 };
            byte[] sig = new byte[] { 0x30, 0x06 };

            Assert.False(CryptoHelper.Verify(badKey, data, sig));
        }

        [Fact]
        public void Verify_RejectsNullPublicKey()
        {
            Assert.False(CryptoHelper.Verify(null, new byte[] { 1 }, new byte[] { 0x30 }));
        }

        // ── Fingerprint ───────────────────────────────────────────────

        [Fact]
        public void ComputeFingerprint_Returns64HexChars()
        {
            var kp = CryptoHelper.GenerateKeyPair();

            string fp = CryptoHelper.ComputeFingerprint(kp.PublicKey);

            Assert.Equal(64, fp.Length);
            Assert.True(fp.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        }

        [Fact]
        public void ComputeFingerprint_Deterministic()
        {
            byte[] key = new byte[65];
            key[0] = 0x04;
            for (int i = 1; i < 65; i++) key[i] = (byte)i;

            Assert.Equal(
                CryptoHelper.ComputeFingerprint(key),
                CryptoHelper.ComputeFingerprint(key));
        }

        // ── Challenge ─────────────────────────────────────────────────

        [Fact]
        public void GenerateChallenge_Returns32Bytes()
        {
            byte[] challenge = CryptoHelper.GenerateChallenge();
            Assert.Equal(32, challenge.Length);
        }

        [Fact]
        public void GenerateChallenge_ProducesUnique()
        {
            byte[] c1 = CryptoHelper.GenerateChallenge();
            byte[] c2 = CryptoHelper.GenerateChallenge();
            Assert.NotEqual(c1, c2);
        }

        // ── Concat ────────────────────────────────────────────────────

        [Fact]
        public void Concat_CombinesArrays()
        {
            byte[] a = new byte[] { 1, 2, 3 };
            byte[] b = new byte[] { 4, 5 };

            byte[] result = CryptoHelper.Concat(a, b);

            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, result);
        }

        [Fact]
        public void Concat_HandlesEmpty()
        {
            byte[] a = new byte[0];
            byte[] b = new byte[] { 1, 2, 3 };

            Assert.Equal(b, CryptoHelper.Concat(a, b));
            Assert.Equal(b, CryptoHelper.Concat(b, a));
        }
    }
}
