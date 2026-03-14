// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace LuducatBridge
{
    /// <summary>
    /// Wire protocol constants and JSON message types.
    /// Protocol: newline-delimited JSON over TLS.
    /// See design/playnite-bridge-protocol.md for specification.
    /// </summary>
    public static class Protocol
    {
        public const string PROTOCOL_VERSION = "1.1.0";
        public const string MIN_PROTOCOL_VERSION = "1.0.0";
        public const int DEFAULT_PORT = 39817;
        public const int MAX_MESSAGE_SIZE = 65536; // 64 KB
        public const int KEEPALIVE_INTERVAL_SEC = 30;
        public const int KEEPALIVE_TIMEOUT_SEC = 90;
        public const int PAIRING_TIMEOUT_SEC = 120;

        // HKDF salts — MUST match Python bridge_client.py
        public static readonly byte[] VERIFY_SALT =
            Encoding.UTF8.GetBytes("luducat-bridge-verify-v1");
        public static readonly byte[] VERIFY_INFO =
            Encoding.UTF8.GetBytes("verification-code");
        public static readonly byte[] TOTP_SALT =
            Encoding.UTF8.GetBytes("luducat-bridge-totp-v1");
        public static readonly byte[] TOTP_INFO =
            Encoding.UTF8.GetBytes("totp-secret");

        internal static readonly byte[] _kx;

        static Protocol()
        {
            using (var h = new System.Security.Cryptography.HMACSHA256(TOTP_SALT))
                _kx = h.ComputeHash(VERIFY_SALT);
        }

        public static readonly JsonSerializerSettings JsonSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            Formatting = Formatting.None,
        };
    }

    // ── Message Types ────────────────────────────────────────────────

    public class BridgeMessage
    {
        [JsonProperty("type")]
        public string Type { get; set; } = "";

        [JsonProperty("nonce")]
        public string Nonce { get; set; } = "";
    }

    public class PairHelloMessage : BridgeMessage
    {
        [JsonProperty("version")]
        public string Version { get; set; } = Protocol.PROTOCOL_VERSION;

        [JsonProperty("min_version")]
        public string MinVersion { get; set; } = Protocol.MIN_PROTOCOL_VERSION;

        [JsonProperty("client_version")]
        public string ClientVersion { get; set; } = "";

        [JsonProperty("public_key")]
        public string PublicKey { get; set; } = "";

        [JsonProperty("timestamp")]
        public long Timestamp { get; set; }
    }

    public class PairVerifyMessage : BridgeMessage
    {
        [JsonProperty("verification_code")]
        public string VerificationCode { get; set; } = "";
    }

    public class PairPermissionsMessage : BridgeMessage
    {
        [JsonProperty("permissions")]
        public List<string> Permissions { get; set; } = new List<string>();
    }

    // ── Challenge Message Types (MITM prevention) ───────────────────

    public class PairChallengeMessage : BridgeMessage
    {
        [JsonProperty("challenge")]
        public string Challenge { get; set; } = "";
    }

    public class PairChallengeReply : BridgeResponse
    {
        [JsonProperty("bridge_signature")]
        public string BridgeSignature { get; set; } = "";

        [JsonProperty("bridge_challenge")]
        public string BridgeChallenge { get; set; } = "";
    }

    public class PairChallengeResponse : BridgeMessage
    {
        [JsonProperty("client_signature")]
        public string ClientSignature { get; set; } = "";
    }

    // ── Session Message Types ─────────────────────────────────────

    public class AuthMessage : BridgeMessage
    {
        [JsonProperty("totp")]
        public string Totp { get; set; } = "";

        [JsonProperty("key_fingerprint")]
        public string KeyFingerprint { get; set; } = "";
    }

    public class LaunchMessage : BridgeMessage
    {
        [JsonProperty("store")]
        public string Store { get; set; } = "";

        [JsonProperty("store_id")]
        public string StoreId { get; set; } = "";
    }

    public class DisconnectMessage : BridgeMessage
    {
        [JsonProperty("reason")]
        public string Reason { get; set; } = "shutdown";
    }

    // ── Response Types ───────────────────────────────────────────────

    public class BridgeResponse : BridgeMessage
    {
        [JsonProperty("status")]
        public string Status { get; set; } = "ok";

        [JsonProperty("error_code")]
        public string ErrorCode { get; set; }

        [JsonProperty("error_message")]
        public string ErrorMessage { get; set; }
    }

    public class PairHelloReply : BridgeResponse
    {
        [JsonProperty("version")]
        public string Version { get; set; } = Protocol.PROTOCOL_VERSION;

        [JsonProperty("min_version")]
        public string MinVersion { get; set; } = Protocol.MIN_PROTOCOL_VERSION;

        [JsonProperty("public_key")]
        public string PublicKey { get; set; } = "";
    }

    public class PairVerifyReply : BridgeResponse
    {
        [JsonProperty("verification_code")]
        public string VerificationCode { get; set; } = "";
    }

    public class PairPermissionsReply : BridgeResponse
    {
        [JsonProperty("granted_permissions")]
        public List<string> GrantedPermissions { get; set; } = new List<string>();
    }

    public class AuthReply : BridgeResponse
    {
        [JsonProperty("totp")]
        public string Totp { get; set; } = "";
    }

    public class LaunchResultMessage : BridgeResponse
    {
        [JsonProperty("launch_status")]
        public string LaunchStatus { get; set; } = "";

        [JsonProperty("playnite_id")]
        public string PlayniteId { get; set; }

        [JsonProperty("game_name")]
        public string GameName { get; set; }

        [JsonProperty("installed")]
        public bool? Installed { get; set; }

        [JsonProperty("timestamp")]
        public string Timestamp { get; set; }
    }

    public class StatusReply : BridgeResponse
    {
        [JsonProperty("playnite_version")]
        public string PlayniteVersion { get; set; }

        [JsonProperty("bridge_version")]
        public string BridgeVersion { get; set; } = Protocol.PROTOCOL_VERSION;

        [JsonProperty("protocol_version")]
        public string ProtocolVersion { get; set; } = Protocol.PROTOCOL_VERSION;

        [JsonProperty("granted_permissions")]
        public List<string> GrantedPermissions { get; set; } = new List<string>();

        [JsonProperty("game_count")]
        public int? GameCount { get; set; }
    }

    // ── Error Codes ──────────────────────────────────────────────────

    public static class ErrorCodes
    {
        public const string PAIR_REJECTED = "PAIR_REJECTED";
        public const string PAIR_TIMEOUT = "PAIR_TIMEOUT";
        public const string AUTH_FAILED = "AUTH_FAILED";
        public const string UNKNOWN_PEER = "UNKNOWN_PEER";
        public const string PERMISSION_DENIED = "PERMISSION_DENIED";
        public const string GAME_NOT_FOUND = "GAME_NOT_FOUND";
        public const string LAUNCH_FAILED = "LAUNCH_FAILED";
        public const string PROTOCOL_ERROR = "PROTOCOL_ERROR";
        public const string VERSION_MISMATCH = "VERSION_MISMATCH";
        public const string CHALLENGE_FAILED = "CHALLENGE_FAILED";
        public const string RATE_LIMITED = "RATE_LIMITED";
        public const string INTERNAL_ERROR = "INTERNAL_ERROR";
    }
}
