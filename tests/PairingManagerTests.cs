// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Reflection;
using Moq;
using Playnite.SDK;
using Xunit;

namespace LuducatBridge.Tests
{
    public class PairingManagerTests
    {
        private readonly Mock<ILogger> _loggerMock;
        private readonly BridgeSettings _settings;

        public PairingManagerTests()
        {
            _loggerMock = new Mock<ILogger>();
            _settings = new BridgeSettings();
            // Wire up callback to prevent NullReferenceException
            _settings.OnPendingPairingChanged = () => { };
        }

        private PairingManager CreateManager()
        {
            return new PairingManager(_settings, _loggerMock.Object);
        }

        private static void SetField(object obj, string name, object value)
        {
            var field = obj.GetType().GetField(name,
                BindingFlags.NonPublic | BindingFlags.Instance);
            field.SetValue(obj, value);
        }

        private static object GetField(object obj, string name)
        {
            var field = obj.GetType().GetField(name,
                BindingFlags.NonPublic | BindingFlags.Instance);
            return field.GetValue(obj);
        }

        // ── IsPaired ──────────────────────────────────────────────────

        [Fact]
        public void IsPaired_FreshInstance_ReturnsFalse()
        {
            var pm = CreateManager();
            Assert.False(pm.IsPaired);
        }

        [Fact]
        public void IsPaired_WithBothKeys_ReturnsTrue()
        {
            var pm = CreateManager();
            SetField(pm, "_peerPublicKey", new byte[65]);
            SetField(pm, "_totpSecret", new byte[20]);

            Assert.True(pm.IsPaired);
        }

        [Fact]
        public void IsPaired_OnlyPeerKey_ReturnsFalse()
        {
            var pm = CreateManager();
            SetField(pm, "_peerPublicKey", new byte[65]);

            Assert.False(pm.IsPaired);
        }

        [Fact]
        public void IsPaired_OnlyTotpSecret_ReturnsFalse()
        {
            var pm = CreateManager();
            SetField(pm, "_totpSecret", new byte[20]);

            Assert.False(pm.IsPaired);
        }

        // ── HasPendingPairing ─────────────────────────────────────────

        [Fact]
        public void HasPendingPairing_FreshInstance_ReturnsFalse()
        {
            var pm = CreateManager();
            Assert.False(pm.HasPendingPairing);
        }

        // ── Unpair ────────────────────────────────────────────────────

        [Fact]
        public void Unpair_ClearsKeyMaterial()
        {
            var pm = CreateManager();
            SetField(pm, "_peerPublicKey", new byte[65]);
            SetField(pm, "_totpSecret", new byte[20]);
            SetField(pm, "_ourPublicKey", new byte[65]);
            SetField(pm, "_ourPrivateKey", new byte[32]);

            Assert.True(pm.IsPaired);
            pm.Unpair();

            Assert.False(pm.IsPaired);
            Assert.Null(pm.GetTotpSecret());
            Assert.Null(pm.GetPeerPublicKey());
        }

        [Fact]
        public void Unpair_ClearsPermissions()
        {
            var pm = CreateManager();
            SetField(pm, "_peerPublicKey", new byte[65]);
            SetField(pm, "_totpSecret", new byte[20]);
            pm.GrantedPermissions.Add("launch");
            Assert.NotEmpty(pm.GrantedPermissions);

            pm.Unpair();

            Assert.Empty(pm.GrantedPermissions);
        }

        // ── GetTotpSecret / GetPeerPublicKey ──────────────────────────

        [Fact]
        public void GetTotpSecret_Fresh_ReturnsNull()
        {
            var pm = CreateManager();
            Assert.Null(pm.GetTotpSecret());
        }

        [Fact]
        public void GetPeerPublicKey_Fresh_ReturnsNull()
        {
            var pm = CreateManager();
            Assert.Null(pm.GetPeerPublicKey());
        }

        [Fact]
        public void GetTotpSecret_AfterSet_ReturnsValue()
        {
            var pm = CreateManager();
            byte[] secret = new byte[] { 1, 2, 3, 4, 5 };
            SetField(pm, "_totpSecret", secret);

            Assert.Equal(secret, pm.GetTotpSecret());
        }

        // ── SubmitPairingCode / CancelPendingPairing ──────────────────

        [Fact]
        public void SubmitPairingCode_NoPending_NoException()
        {
            var pm = CreateManager();
            // Should not throw when no pending pairing
            pm.SubmitPairingCode("123456");
        }

        [Fact]
        public void CancelPendingPairing_NoPending_NoException()
        {
            var pm = CreateManager();
            // Should not throw when no pending pairing
            pm.CancelPendingPairing();
        }

        // ── PendingPeerAddress / PendingPeerVersion ───────────────────

        [Fact]
        public void PendingPeerAddress_Fresh_ReturnsNull()
        {
            var pm = CreateManager();
            Assert.Null(pm.PendingPeerAddress);
        }

        [Fact]
        public void PendingPeerVersion_Fresh_ReturnsNull()
        {
            var pm = CreateManager();
            Assert.Null(pm.PendingPeerVersion);
        }

        // ── GrantedPermissions ────────────────────────────────────────

        [Fact]
        public void GrantedPermissions_Fresh_IsEmpty()
        {
            var pm = CreateManager();
            Assert.NotNull(pm.GrantedPermissions);
            Assert.Empty(pm.GrantedPermissions);
        }
    }
}
