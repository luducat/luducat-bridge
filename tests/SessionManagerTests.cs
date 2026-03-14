// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Reflection;
using Moq;
using Newtonsoft.Json.Linq;
using Playnite.SDK;
using Xunit;

namespace LuducatBridge.Tests
{
    public class SessionManagerTests
    {
        private readonly Mock<ILogger> _loggerMock;
        private readonly BridgeSettings _settings;

        public SessionManagerTests()
        {
            _loggerMock = new Mock<ILogger>();
            _settings = new BridgeSettings();
        }

        /// <summary>
        /// Create a PairingManager with injected key state (bypassing credential store).
        /// </summary>
        private PairingManager CreatePairingManagerWithState(
            byte[] peerPublicKey = null,
            byte[] totpSecret = null)
        {
            var pm = new PairingManager(_settings, _loggerMock.Object);

            if (peerPublicKey != null)
                SetField(pm, "_peerPublicKey", peerPublicKey);
            if (totpSecret != null)
                SetField(pm, "_totpSecret", totpSecret);

            return pm;
        }

        private static void SetField(object obj, string name, object value)
        {
            var field = obj.GetType().GetField(name,
                BindingFlags.NonPublic | BindingFlags.Instance);
            field.SetValue(obj, value);
        }

        private static JObject MakeAuthMsg(string totp, string fingerprint = "abcd1234")
        {
            return new JObject
            {
                ["type"] = "auth",
                ["totp"] = totp,
                ["key_fingerprint"] = fingerprint,
            };
        }

        // ── Not Paired ────────────────────────────────────────────────

        [Fact]
        public void ValidateAuth_NotPaired_ReturnsFalse()
        {
            var pm = CreatePairingManagerWithState();
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            Assert.False(sm.ValidateAuth(MakeAuthMsg("123456")));
        }

        // ── No TOTP Secret ────────────────────────────────────────────

        [Fact]
        public void ValidateAuth_NoTotpSecret_ReturnsFalse()
        {
            // Paired (peer key set) but no TOTP secret — edge case
            var pm = CreatePairingManagerWithState(
                peerPublicKey: new byte[65]);
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            Assert.False(sm.ValidateAuth(MakeAuthMsg("123456")));
        }

        // ── Valid TOTP ────────────────────────────────────────────────

        [Fact]
        public void ValidateAuth_ValidTotp_ReturnsTrue()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 1);

            byte[] peerKey = new byte[65];
            peerKey[0] = 0x04;

            var pm = CreatePairingManagerWithState(
                peerPublicKey: peerKey,
                totpSecret: secret);
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            // Compute current valid TOTP
            string validTotp = CryptoHelper.ComputeTotp(secret, 0);

            Assert.True(sm.ValidateAuth(MakeAuthMsg(validTotp)));
        }

        // ── Invalid TOTP ──────────────────────────────────────────────

        [Fact]
        public void ValidateAuth_InvalidTotp_ReturnsFalse()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 1);

            byte[] peerKey = new byte[65];
            peerKey[0] = 0x04;

            var pm = CreatePairingManagerWithState(
                peerPublicKey: peerKey,
                totpSecret: secret);
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            Assert.False(sm.ValidateAuth(MakeAuthMsg("000000")));
        }

        // ── Empty TOTP ────────────────────────────────────────────────

        [Fact]
        public void ValidateAuth_EmptyTotp_ReturnsFalse()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 1);

            byte[] peerKey = new byte[65];
            peerKey[0] = 0x04;

            var pm = CreatePairingManagerWithState(
                peerPublicKey: peerKey,
                totpSecret: secret);
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            Assert.False(sm.ValidateAuth(MakeAuthMsg("")));
        }

        // ── ComputeCurrentTotp ────────────────────────────────────────

        [Fact]
        public void ComputeCurrentTotp_NoPairing_ReturnsEmpty()
        {
            var pm = CreatePairingManagerWithState();
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            Assert.Equal("", sm.ComputeCurrentTotp());
        }

        [Fact]
        public void ComputeCurrentTotp_WithSecret_Returns6Digits()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 42);

            byte[] peerKey = new byte[65];
            peerKey[0] = 0x04;

            var pm = CreatePairingManagerWithState(
                peerPublicKey: peerKey,
                totpSecret: secret);
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            string totp = sm.ComputeCurrentTotp();

            Assert.Equal(6, totp.Length);
            Assert.True(int.TryParse(totp, out _));
        }

        // ── Mutual Auth Round-Trip ────────────────────────────────────

        [Fact]
        public void MutualAuth_ComputeAndValidate_Succeeds()
        {
            byte[] secret = new byte[20];
            for (int i = 0; i < 20; i++) secret[i] = (byte)(i + 99);

            byte[] peerKey = new byte[65];
            peerKey[0] = 0x04;

            var pm = CreatePairingManagerWithState(
                peerPublicKey: peerKey,
                totpSecret: secret);
            var sm = new SessionManager(pm, _settings, _loggerMock.Object);

            string bridgeTotp = sm.ComputeCurrentTotp();
            // The bridge's TOTP should validate against the same secret
            Assert.True(CryptoHelper.VerifyTotp(secret, bridgeTotp));
        }
    }
}
