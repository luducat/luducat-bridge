// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Collections.Generic;
using Xunit;

namespace LuducatBridge.Tests
{
    public class BridgeSettingsTests
    {
        // ── Defaults ──────────────────────────────────────────────────

        [Fact]
        public void DefaultPort_Is39817()
        {
            var settings = new BridgeSettings();
            Assert.Equal(Protocol.DEFAULT_PORT, settings.Port);
        }

        [Fact]
        public void DefaultAlwaysAllow_IsFalse()
        {
            var settings = new BridgeSettings();
            Assert.False(settings.AlwaysAllow);
        }

        [Fact]
        public void DefaultDebugLogging_IsFalse()
        {
            var settings = new BridgeSettings();
            Assert.False(settings.DebugLogging);
        }

        [Fact]
        public void DefaultShareFlags_AreFalse()
        {
            var settings = new BridgeSettings();
            Assert.False(settings.ShareFavorites);
            Assert.False(settings.ShareTags);
            Assert.False(settings.SharePlaytime);
        }

        // ── Port Validation ───────────────────────────────────────────

        [Fact]
        public void VerifySettings_ValidPort_ReturnsTrue()
        {
            var settings = new BridgeSettings { Port = 39817 };
            List<string> errors;
            Assert.True(settings.VerifySettings(out errors));
        }

        [Fact]
        public void VerifySettings_MinPort_ReturnsTrue()
        {
            var settings = new BridgeSettings { Port = 1024 };
            List<string> errors;
            Assert.True(settings.VerifySettings(out errors));
        }

        [Fact]
        public void VerifySettings_MaxPort_ReturnsTrue()
        {
            var settings = new BridgeSettings { Port = 65535 };
            List<string> errors;
            Assert.True(settings.VerifySettings(out errors));
        }

        [Fact]
        public void VerifySettings_PortTooLow_ReturnsFalse()
        {
            var settings = new BridgeSettings { Port = 1023 };
            List<string> errors;
            Assert.False(settings.VerifySettings(out errors));
            Assert.NotEmpty(errors);
        }

        [Fact]
        public void VerifySettings_PortTooHigh_ReturnsFalse()
        {
            var settings = new BridgeSettings { Port = 65536 };
            List<string> errors;
            Assert.False(settings.VerifySettings(out errors));
            Assert.NotEmpty(errors);
        }

        [Fact]
        public void VerifySettings_PortZero_ReturnsFalse()
        {
            var settings = new BridgeSettings { Port = 0 };
            List<string> errors;
            Assert.False(settings.VerifySettings(out errors));
        }

        // ── Callback Defaults ─────────────────────────────────────────

        [Fact]
        public void RuntimeCallbacks_DefaultToNull()
        {
            var settings = new BridgeSettings();
            Assert.Null(settings.OnUnpairRequested);
            Assert.Null(settings.GetStatusText);
            Assert.Null(settings.GetIsPaired);
            Assert.Null(settings.OnPendingPairingChanged);
            Assert.Null(settings.GetHasPendingPairing);
            Assert.Null(settings.GetPendingPeerInfo);
            Assert.Null(settings.SubmitPairingCode);
            Assert.Null(settings.CancelPendingPairing);
        }

        // ── Callbacks Invocable ───────────────────────────────────────

        [Fact]
        public void SubmitPairingCode_Callback_Invoked()
        {
            var settings = new BridgeSettings();
            string captured = null;
            settings.SubmitPairingCode = (code) => { captured = code; };

            settings.SubmitPairingCode("123456");

            Assert.Equal("123456", captured);
        }

        [Fact]
        public void GetIsPaired_Callback_ReturnsValue()
        {
            var settings = new BridgeSettings();
            settings.GetIsPaired = () => true;

            Assert.True(settings.GetIsPaired());
        }
    }
}
