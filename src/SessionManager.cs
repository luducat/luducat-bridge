// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using Newtonsoft.Json.Linq;
using Playnite.SDK;

namespace LuducatBridge
{
    /// <summary>
    /// HMAC-TOTP session management for the Playnite bridge.
    /// Handles silent reconnection after TLS connection drops.
    /// </summary>
    public class SessionManager
    {
        private readonly PairingManager _pairing;
        private readonly BridgeSettings _settings;
        private readonly ILogger _logger;

        public SessionManager(PairingManager pairing, BridgeSettings settings, ILogger logger)
        {
            _pairing = pairing;
            _settings = settings;
            _logger = logger;
        }

        /// <summary>
        /// Validate an auth message from the client.
        /// Checks TOTP value against the shared secret.
        /// </summary>
        public bool ValidateAuth(JObject authMsg)
        {
            if (!_pairing.IsPaired)
            {
                _logger.Warn("Authentication rejected: not paired");
                return false;
            }

            string clientTotp = authMsg["totp"]?.ToString() ?? "";
            string fingerprint = authMsg["key_fingerprint"]?.ToString() ?? "";

            var totpSecret = _pairing.GetTotpSecret();
            if (totpSecret == null)
            {
                _logger.Warn("Authentication failed: no TOTP secret");
                return false;
            }

            bool valid = CryptoHelper.VerifyTotp(totpSecret, clientTotp);
            if (valid)
            {
                string fpShort = fingerprint.Length >= 8
                    ? fingerprint.Substring(0, 8) : fingerprint;
                _logger.Info($"Authentication succeeded (fingerprint: {fpShort})");
            }
            else
            {
                _logger.Warn("Authentication failed: TOTP mismatch");
            }

            return valid;
        }

        /// <summary>
        /// Compute the current TOTP value for mutual authentication.
        /// </summary>
        public string ComputeCurrentTotp()
        {
            var secret = _pairing.GetTotpSecret();
            if (secret == null)
                return "";

            return CryptoHelper.ComputeTotp(secret, 0);
        }
    }
}
