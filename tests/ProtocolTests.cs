// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Text;
using Newtonsoft.Json;
using Xunit;

namespace LuducatBridge.Tests
{
    public class ProtocolTests
    {
        // ── Constants ─────────────────────────────────────────────────

        [Fact]
        public void ProtocolVersion_Is1_1_0()
        {
            Assert.Equal("1.1.0", Protocol.PROTOCOL_VERSION);
        }

        [Fact]
        public void MinProtocolVersion_Is1_0_0()
        {
            Assert.Equal("1.0.0", Protocol.MIN_PROTOCOL_VERSION);
        }

        [Fact]
        public void DefaultPort_Is39817()
        {
            Assert.Equal(39817, Protocol.DEFAULT_PORT);
        }

        [Fact]
        public void MaxMessageSize_Is64KB()
        {
            Assert.Equal(65536, Protocol.MAX_MESSAGE_SIZE);
        }

        [Fact]
        public void PairingTimeout_Is120Seconds()
        {
            Assert.Equal(120, Protocol.PAIRING_TIMEOUT_SEC);
        }

        // ── HKDF Salts Match Python ───────────────────────────────────

        [Fact]
        public void VerifySalt_MatchesPython()
        {
            Assert.Equal(
                "luducat-bridge-verify-v1",
                Encoding.UTF8.GetString(Protocol.VERIFY_SALT));
        }

        [Fact]
        public void VerifyInfo_MatchesPython()
        {
            Assert.Equal(
                "verification-code",
                Encoding.UTF8.GetString(Protocol.VERIFY_INFO));
        }

        [Fact]
        public void TotpSalt_MatchesPython()
        {
            Assert.Equal(
                "luducat-bridge-totp-v1",
                Encoding.UTF8.GetString(Protocol.TOTP_SALT));
        }

        [Fact]
        public void TotpInfo_MatchesPython()
        {
            Assert.Equal(
                "totp-secret",
                Encoding.UTF8.GetString(Protocol.TOTP_INFO));
        }

        // ── Derived Key Material ──────────────────────────────────────

        [Fact]
        public void Kx_IsNotNull()
        {
            Assert.NotNull(Protocol._kx);
        }

        [Fact]
        public void Kx_Is32Bytes()
        {
            Assert.Equal(32, Protocol._kx.Length);
        }

        [Fact]
        public void Kx_MatchesHmacSha256()
        {
            // _kx = HMAC-SHA256(TOTP_SALT, VERIFY_SALT)
            using (var h = new System.Security.Cryptography.HMACSHA256(Protocol.TOTP_SALT))
            {
                byte[] expected = h.ComputeHash(Protocol.VERIFY_SALT);
                Assert.Equal(expected, Protocol._kx);
            }
        }

        // ── JSON Settings ─────────────────────────────────────────────

        [Fact]
        public void JsonSettings_IgnoresNulls()
        {
            Assert.Equal(
                NullValueHandling.Ignore,
                Protocol.JsonSettings.NullValueHandling);
        }

        [Fact]
        public void JsonSettings_NoFormatting()
        {
            Assert.Equal(
                Formatting.None,
                Protocol.JsonSettings.Formatting);
        }

        // ── Message Types ─────────────────────────────────────────────

        [Fact]
        public void PairHelloMessage_DefaultValues()
        {
            var msg = new PairHelloMessage();

            Assert.Equal(Protocol.PROTOCOL_VERSION, msg.Version);
            Assert.Equal(Protocol.MIN_PROTOCOL_VERSION, msg.MinVersion);
            Assert.Equal("", msg.ClientVersion);
            Assert.Equal("", msg.PublicKey);
            Assert.Equal(0, msg.Timestamp);
        }

        [Fact]
        public void PairHelloReply_DefaultValues()
        {
            var msg = new PairHelloReply();

            Assert.Equal(Protocol.PROTOCOL_VERSION, msg.Version);
            Assert.Equal(Protocol.MIN_PROTOCOL_VERSION, msg.MinVersion);
            Assert.Equal("ok", msg.Status);
        }

        [Fact]
        public void LaunchResultMessage_Serialization()
        {
            var msg = new LaunchResultMessage
            {
                Type = "launch_result",
                Nonce = "abc123",
                LaunchStatus = "started",
                PlayniteId = "guid-here",
                GameName = "Test Game",
                Installed = true,
            };

            string json = JsonConvert.SerializeObject(msg, Protocol.JsonSettings);

            Assert.Contains("\"launch_status\":\"started\"", json);
            Assert.Contains("\"game_name\":\"Test Game\"", json);
            Assert.Contains("\"installed\":true", json);
        }

        [Fact]
        public void BridgeResponse_ErrorSerialization()
        {
            var msg = new BridgeResponse
            {
                Type = "error",
                Status = "error",
                ErrorCode = ErrorCodes.GAME_NOT_FOUND,
                ErrorMessage = "Not found",
            };

            string json = JsonConvert.SerializeObject(msg, Protocol.JsonSettings);

            Assert.Contains("\"error_code\":\"GAME_NOT_FOUND\"", json);
            Assert.Contains("\"error_message\":\"Not found\"", json);
        }

        // ── Error Codes ───────────────────────────────────────────────

        [Fact]
        public void ErrorCodes_AllDefined()
        {
            Assert.Equal("PAIR_REJECTED", ErrorCodes.PAIR_REJECTED);
            Assert.Equal("PAIR_TIMEOUT", ErrorCodes.PAIR_TIMEOUT);
            Assert.Equal("AUTH_FAILED", ErrorCodes.AUTH_FAILED);
            Assert.Equal("GAME_NOT_FOUND", ErrorCodes.GAME_NOT_FOUND);
            Assert.Equal("LAUNCH_FAILED", ErrorCodes.LAUNCH_FAILED);
            Assert.Equal("PROTOCOL_ERROR", ErrorCodes.PROTOCOL_ERROR);
            Assert.Equal("VERSION_MISMATCH", ErrorCodes.VERSION_MISMATCH);
            Assert.Equal("CHALLENGE_FAILED", ErrorCodes.CHALLENGE_FAILED);
            Assert.Equal("RATE_LIMITED", ErrorCodes.RATE_LIMITED);
            Assert.Equal("INTERNAL_ERROR", ErrorCodes.INTERNAL_ERROR);
        }
    }
}
