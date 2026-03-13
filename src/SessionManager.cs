// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using Newtonsoft.Json.Linq;

namespace LuducatBridge
{
    /// <summary>
    /// HMAC-TOTP session management for the Playnite bridge.
    /// Handles silent reconnection after TLS connection drops.
    /// </summary>
    public class SessionManager
    {
        private readonly PairingManager _pairing;

        public SessionManager(PairingManager pairing)
        {
            _pairing = pairing;
        }

        /// <summary>
        /// Validate an auth message from the client.
        /// Checks TOTP value against the shared secret.
        /// </summary>
        public bool ValidateAuth(JObject authMsg)
        {
            if (!_pairing.IsPaired)
                return false;

            string clientTotp = authMsg["totp"]?.ToString() ?? "";

            var totpSecret = _pairing.GetTotpSecret();
            if (totpSecret == null)
                return false;

            return CryptoHelper.VerifyTotp(totpSecret, clientTotp);
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
