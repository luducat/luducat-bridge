// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using AdysTech.CredentialManager;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Playnite.SDK;

namespace LuducatBridge
{
    /// <summary>
    /// Handles key generation, HKDF verification code derivation,
    /// and the pairing handshake. Stores pairing credentials via
    /// CredentialManager (Windows DPAPI).
    /// </summary>
    public class PairingManager
    {
        private const string CREDENTIAL_TARGET = "luducat-bridge-pairing";
        private const string CERT_CREDENTIAL_TARGET = "luducat-bridge-cert";

        private readonly BridgeSettings _settings;
        private readonly ILogger _logger;

        // Key material
        private byte[] _ourPrivateKey;
        private byte[] _ourPublicKey;
        private byte[] _peerPublicKey;
        private byte[] _totpSecret;
        private byte[] _ourCngPrivateBlob;
        private List<string> _grantedPermissions = new List<string>();

        // TLS certificate (self-signed, persisted)
        private X509Certificate2 _serverCert;

        // Rate limiting for verification attempts
        private int _failedVerifyAttempts;
        private DateTime _verifyLockoutUntil = DateTime.MinValue;
        private const int MAX_VERIFY_ATTEMPTS = 3;
        private static readonly TimeSpan VERIFY_LOCKOUT_DURATION = TimeSpan.FromMinutes(5);

        // Pending pairing state — waits for Playnite user to enter code
        private TaskCompletionSource<string> _pendingCodeTcs;
        private string _pendingPeerAddress;
        private string _pendingPeerVersion;
        private string _pendingDerivedCode;

        public bool IsPaired
        {
            get { return _peerPublicKey != null && _totpSecret != null; }
        }

        public bool HasPendingPairing
        {
            get { return _pendingCodeTcs != null; }
        }

        public string PendingPeerAddress
        {
            get { return _pendingPeerAddress; }
        }

        public string PendingPeerVersion
        {
            get { return _pendingPeerVersion; }
        }

        public List<string> GrantedPermissions
        {
            get { return _grantedPermissions; }
        }

        public PairingManager(BridgeSettings settings, ILogger logger)
        {
            _settings = settings;
            _logger = logger;
            LoadCredentials();
        }

        // ── Public API ───────────────────────────────────────────────

        public byte[] GetTotpSecret() { return _totpSecret; }
        public byte[] GetPeerPublicKey() { return _peerPublicKey; }

        /// <summary>
        /// Get or create the self-signed TLS server certificate.
        /// Persisted across restarts via the Windows certificate store.
        /// </summary>
        public X509Certificate2 GetOrCreateServerCertificate()
        {
            if (_serverCert != null)
                return _serverCert;

            // Try loading from credential store
            _serverCert = LoadCertificate();
            if (_serverCert != null)
            {
                if (_settings.DebugLogging)
                    _logger.Debug("Server certificate loaded from credential store");
                return _serverCert;
            }

            // Generate self-signed certificate via Windows cert store API
            _serverCert = SelfSignedCertHelper.CreateSelfSigned("CN=luducat-bridge");

            if (_serverCert != null)
            {
                _logger.Info("New self-signed TLS certificate generated");
                SaveCertificate(_serverCert);
            }

            return _serverCert;
        }

        /// <summary>
        /// Handle pairing handshake over an already-established TLS stream.
        /// </summary>
        public async Task HandlePairHello(
            Stream stream, JObject helloMsg, X509Certificate2 serverCert,
            string remoteAddress)
        {
            string nonce = helloMsg["nonce"]?.ToString() ?? "";
            string peerPubKeyB64 = helloMsg["public_key"]?.ToString() ?? "";
            string peerVersion = helloMsg["version"]?.ToString() ?? "";
            string peerMinVersion = helloMsg["min_version"]?.ToString() ?? "";
            string clientVersion = helloMsg["client_version"]?.ToString() ?? "";
            long peerTimestamp = helloMsg["timestamp"]?.ToObject<long>() ?? 0;

            _logger.Info("Pairing handshake started");

            // ── Pairing lock: reject if already paired ────────────────
            if (IsPaired)
            {
                _logger.Warn("Pairing rejected: already paired");
                await SendError(stream, "pair_hello_reply", nonce,
                    ErrorCodes.PAIR_REJECTED,
                    "Already paired. Unpair first.");
                return;
            }

            // ── Rate limiting: check lockout ──────────────────────────
            if (DateTime.UtcNow < _verifyLockoutUntil)
            {
                _logger.Warn("Pairing rejected: rate limited");
                await SendError(stream, "pair_hello_reply", nonce,
                    ErrorCodes.RATE_LIMITED,
                    "Too many failed attempts. Try again later.");
                return;
            }

            // Version check — peer version must be >= our min, our version must be >= peer min
            if (!peerVersion.StartsWith("1."))
            {
                _logger.Warn($"Pairing rejected: incompatible version {peerVersion}");
                await SendError(stream, "pair_hello_reply", nonce,
                    ErrorCodes.VERSION_MISMATCH,
                    $"Incompatible protocol version: {peerVersion}");
                return;
            }

            if (!string.IsNullOrEmpty(peerMinVersion) && !peerMinVersion.StartsWith("1."))
            {
                _logger.Warn($"Pairing rejected: peer requires min version {peerMinVersion}");
                await SendError(stream, "pair_hello_reply", nonce,
                    ErrorCodes.VERSION_MISMATCH,
                    $"Cannot satisfy minimum protocol version: {peerMinVersion}");
                return;
            }

            // Validate timestamp within ±1 window (5-minute windows)
            long ourTsWindow = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 300;
            long tsWindow = peerTimestamp;
            if (tsWindow == 0)
            {
                tsWindow = ourTsWindow;
            }
            else if (Math.Abs(tsWindow - ourTsWindow) > 1)
            {
                _logger.Warn($"Pairing rejected: timestamp too far off (peer={tsWindow}, ours={ourTsWindow})");
                await SendError(stream, "pair_hello_reply", nonce,
                    ErrorCodes.PAIR_REJECTED,
                    "Clock skew too large");
                return;
            }

            // Generate our ECDSA P-256 keypair
            var keyPair = CryptoHelper.GenerateKeyPair();
            _ourPrivateKey = keyPair.PrivateKey;
            _ourPublicKey = keyPair.PublicKey;
            _ourCngPrivateBlob = keyPair.CngPrivateBlob;
            _peerPublicKey = Convert.FromBase64String(peerPubKeyB64);

            _logger.Info("Key exchange complete");

            // Send our public key
            var reply = new PairHelloReply
            {
                Type = "pair_hello_reply",
                Nonce = nonce,
                PublicKey = Convert.ToBase64String(_ourPublicKey),
            };
            await SendJson(stream, reply);

            // ── Wait for pair_verify ──────────────────────────────────
            var verifyMsg = await ReadJson(stream);
            if (verifyMsg == null) return;

            string verifyNonce = verifyMsg["nonce"]?.ToString() ?? "";
            string peerCode = verifyMsg["verification_code"]?.ToString() ?? "";

            // Derive verification code with cert and timestamp binding
            byte[] certDer = serverCert?.RawData;
            string ourCode = CryptoHelper.DeriveVerificationCode(
                _ourPublicKey, _peerPublicKey, certDer, tsWindow);

            if (!string.Equals(peerCode, ourCode, StringComparison.Ordinal))
            {
                _failedVerifyAttempts++;
                if (_failedVerifyAttempts >= MAX_VERIFY_ATTEMPTS)
                {
                    _logger.Warn($"Rate limited — locked for {VERIFY_LOCKOUT_DURATION.TotalMinutes} minutes");
                    _verifyLockoutUntil = DateTime.UtcNow + VERIFY_LOCKOUT_DURATION;
                    await SendError(stream, "pair_verify_reply", verifyNonce,
                        ErrorCodes.RATE_LIMITED,
                        $"Too many failed attempts. Locked out for {VERIFY_LOCKOUT_DURATION.TotalMinutes} minutes.");
                }
                else
                {
                    _logger.Warn($"Verification code mismatch (attempt {_failedVerifyAttempts}/{MAX_VERIFY_ATTEMPTS})");
                    await SendError(stream, "pair_verify_reply", verifyNonce,
                        ErrorCodes.PAIR_REJECTED, "Verification code mismatch");
                }
                ClearKeyMaterial();
                return;
            }

            _failedVerifyAttempts = 0;
            _logger.Info("Verification codes match programmatically");

            // ── Wait for Playnite user to enter the code ──────────────
            _pendingDerivedCode = ourCode;
            string userCode = await WaitForUserCodeEntry(
                remoteAddress, clientVersion, Protocol.PAIRING_TIMEOUT_SEC * 1000);

            if (userCode == null)
            {
                _logger.Info("Pairing timed out or was cancelled by Playnite user");
                await SendError(stream, "pair_verify_reply", verifyNonce,
                    ErrorCodes.PAIR_REJECTED,
                    "Playnite user did not confirm the pairing");
                ClearKeyMaterial();
                return;
            }

            userCode = userCode.Replace(" ", "").Trim();
            if (!string.Equals(userCode, ourCode, StringComparison.Ordinal))
            {
                _logger.Warn("Playnite user entered wrong verification code");
                await SendError(stream, "pair_verify_reply", verifyNonce,
                    ErrorCodes.PAIR_REJECTED,
                    "Verification code mismatch");
                ClearKeyMaterial();
                return;
            }

            _logger.Info("Playnite user entered correct verification code");

            // Send verify reply
            var verifyReply = new PairVerifyReply
            {
                Type = "pair_verify_reply",
                Nonce = verifyNonce,
                VerificationCode = ourCode,
            };
            await SendJson(stream, verifyReply);

            // ── Signature challenge (MITM prevention) ─────────────────
            // Wait for pair_challenge from client
            var challengeMsg = await ReadJson(stream);
            if (challengeMsg == null) return;

            string challengeNonce = challengeMsg["nonce"]?.ToString() ?? "";
            string clientChallengeHex = challengeMsg["challenge"]?.ToString() ?? "";
            byte[] clientChallenge = HexToBytes(clientChallengeHex);

            // Sign: challenge || peer_public_key
            byte[] signPayload = CryptoHelper.Concat(clientChallenge, _peerPublicKey);
            byte[] bridgeSig = CryptoHelper.Sign(_ourCngPrivateBlob, signPayload);

            // Generate our challenge for the client
            byte[] bridgeChallenge = CryptoHelper.GenerateChallenge();

            var challengeReply = new PairChallengeReply
            {
                Type = "pair_challenge_reply",
                Nonce = challengeNonce,
                BridgeSignature = Convert.ToBase64String(bridgeSig),
                BridgeChallenge = BitConverter.ToString(bridgeChallenge).Replace("-", "").ToLowerInvariant(),
            };
            await SendJson(stream, challengeReply);

            // Wait for pair_challenge_response with client's signature
            var challengeRespMsg = await ReadJson(stream);
            if (challengeRespMsg == null) return;

            string respNonce = challengeRespMsg["nonce"]?.ToString() ?? "";
            string clientSigB64 = challengeRespMsg["client_signature"]?.ToString() ?? "";
            byte[] clientSig = Convert.FromBase64String(clientSigB64);

            // Verify: client signed (bridge_challenge || bridge_public_key)
            byte[] verifyPayload = CryptoHelper.Concat(bridgeChallenge, _ourPublicKey);
            if (!CryptoHelper.Verify(_peerPublicKey, verifyPayload, clientSig))
            {
                _logger.Warn("Challenge signature invalid (possible MITM)");
                await SendError(stream, "pair_challenge_verify", respNonce,
                    ErrorCodes.CHALLENGE_FAILED,
                    "Client signature verification failed — possible MITM");
                ClearKeyMaterial();
                return;
            }

            _logger.Info("Challenge verified");

            // Send challenge verified confirmation
            var challengeOk = new BridgeResponse
            {
                Type = "pair_challenge_verify",
                Nonce = respNonce,
            };
            await SendJson(stream, challengeOk);

            // ── Wait for permissions ──────────────────────────────────
            var permMsg = await ReadJson(stream);
            if (permMsg == null) return;

            string permNonce = permMsg["nonce"]?.ToString() ?? "";
            var permissions = permMsg["permissions"]?
                .Select(p => p.ToString())
                .Where(p => !string.IsNullOrEmpty(p))
                .ToList() ?? new List<string>();

            // Only "launch" is currently supported
            _grantedPermissions = permissions.Where(p => string.Equals(p, "launch", StringComparison.Ordinal)).ToList();

            _logger.Info($"Permissions granted: [{string.Join(", ", _grantedPermissions)}]");

            var permReply = new PairPermissionsReply
            {
                Type = "pair_permissions_reply",
                Nonce = permNonce,
                GrantedPermissions = _grantedPermissions,
            };
            await SendJson(stream, permReply);

            // ── Wait for pair_complete ─────────────────────────────────
            var completeMsg = await ReadJson(stream);
            if (completeMsg == null) return;

            string completeNonce = completeMsg["nonce"]?.ToString() ?? "";

            // Derive TOTP secret
            _totpSecret = CryptoHelper.DeriveTotpSecret(_ourPublicKey, _peerPublicKey);

            // Store credentials
            SaveCredentials();

            _logger.Info("Pairing complete — credentials saved");

            var completeReply = new BridgeResponse
            {
                Type = "pair_complete_reply",
                Nonce = completeNonce,
            };
            await SendJson(stream, completeReply);
        }

        public void SubmitPairingCode(string code)
        {
            _pendingCodeTcs?.TrySetResult(code);
        }

        public void CancelPendingPairing()
        {
            _pendingCodeTcs?.TrySetResult(null);
        }

        private async Task<string> WaitForUserCodeEntry(
            string peerAddress, string peerVersion, int timeoutMs)
        {
            _pendingCodeTcs = new TaskCompletionSource<string>();
            _pendingPeerAddress = peerAddress;
            _pendingPeerVersion = peerVersion;
            _settings.OnPendingPairingChanged?.Invoke();

            string result;
            using (var cts = new CancellationTokenSource(timeoutMs))
            {
                cts.Token.Register(() => _pendingCodeTcs.TrySetResult(null));
                result = await _pendingCodeTcs.Task;
            }

            _pendingCodeTcs = null;
            _pendingPeerAddress = null;
            _pendingPeerVersion = null;
            _pendingDerivedCode = null;
            _settings.OnPendingPairingChanged?.Invoke();

            return result;
        }

        public void Unpair()
        {
            _logger.Info("Unpair requested — credentials cleared");
            ClearKeyMaterial();
            DeleteCredentials();
        }

        // ── Certificate Storage ──────────────────────────────────────

        private static void SaveCertificate(X509Certificate2 cert)
        {
            try
            {
                byte[] pfxBytes = cert.Export(X509ContentType.Pfx, "luducat-bridge");
                string pfxB64 = Convert.ToBase64String(pfxBytes);
                CredentialManager.SaveCredentials(
                    CERT_CREDENTIAL_TARGET,
                    new NetworkCredential("luducat-bridge-cert", pfxB64));
            }
            catch (Exception) { }
        }

        private static X509Certificate2 LoadCertificate()
        {
            try
            {
                var cred = CredentialManager.GetCredentials(CERT_CREDENTIAL_TARGET);
                if (cred?.Password == null) return null;

                byte[] pfxBytes = Convert.FromBase64String(cred.Password);
                return new X509Certificate2(pfxBytes, "luducat-bridge",
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }
            catch (Exception)
            {
                return null;
            }
        }

        // ── Credential Storage ───────────────────────────────────────

        private void SaveCredentials()
        {
            var data = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["peer_public_key"] = _peerPublicKey != null
                    ? Convert.ToBase64String(_peerPublicKey) : null,
                ["totp_secret"] = _totpSecret != null
                    ? Convert.ToBase64String(_totpSecret) : null,
                ["our_public_key"] = _ourPublicKey != null
                    ? Convert.ToBase64String(_ourPublicKey) : null,
                ["our_private_key"] = _ourPrivateKey != null
                    ? Convert.ToBase64String(_ourPrivateKey) : null,
                ["permissions"] = string.Join(",", _grantedPermissions),
            };

            string json = JsonConvert.SerializeObject(data);

            try
            {
                CredentialManager.SaveCredentials(
                    CREDENTIAL_TARGET,
                    new NetworkCredential("luducat-bridge", json));
            }
            catch (Exception) { }
        }

        private void LoadCredentials()
        {
            try
            {
                var cred = CredentialManager.GetCredentials(CREDENTIAL_TARGET);
                if (cred?.Password == null) return;

                var data = JsonConvert.DeserializeObject<Dictionary<string, string>>(cred.Password);
                if (data == null) return;

                string val;
                if (data.TryGetValue("peer_public_key", out val) && val != null)
                    _peerPublicKey = Convert.FromBase64String(val);

                if (data.TryGetValue("totp_secret", out val) && val != null)
                    _totpSecret = Convert.FromBase64String(val);

                if (data.TryGetValue("our_public_key", out val) && val != null)
                    _ourPublicKey = Convert.FromBase64String(val);

                if (data.TryGetValue("our_private_key", out val) && val != null)
                {
                    _ourPrivateKey = Convert.FromBase64String(val);
                    // Reconstruct CNG private blob from stored key material
                    if (_ourPublicKey != null && _ourPublicKey.Length == 65
                        && _ourPrivateKey != null && _ourPrivateKey.Length == 32)
                    {
                        // CNG EccPrivateBlob: Magic(4) + KeyLen(4) + X(32) + Y(32) + D(32)
                        _ourCngPrivateBlob = new byte[104];
                        // Magic: ECS2 = 0x32534345
                        _ourCngPrivateBlob[0] = 0x45; _ourCngPrivateBlob[1] = 0x43;
                        _ourCngPrivateBlob[2] = 0x53; _ourCngPrivateBlob[3] = 0x32;
                        // Key length: 32
                        _ourCngPrivateBlob[4] = 0x20;
                        // X, Y from public key (skip 0x04 prefix)
                        Array.Copy(_ourPublicKey, 1, _ourCngPrivateBlob, 8, 32);
                        Array.Copy(_ourPublicKey, 33, _ourCngPrivateBlob, 40, 32);
                        // D (private key)
                        Array.Copy(_ourPrivateKey, 0, _ourCngPrivateBlob, 72, 32);
                    }
                }

                if (data.TryGetValue("permissions", out val) && val != null)
                    _grantedPermissions = val.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).ToList();
            }
            catch (Exception) { }
        }

        private static void DeleteCredentials()
        {
            try { CredentialManager.RemoveCredentials(CREDENTIAL_TARGET); } catch { }
            try { CredentialManager.RemoveCredentials(CERT_CREDENTIAL_TARGET); } catch { }
        }

        private void ClearKeyMaterial()
        {
            _ourPrivateKey = null;
            _ourPublicKey = null;
            _peerPublicKey = null;
            _totpSecret = null;
            _ourCngPrivateBlob = null;
            _grantedPermissions.Clear();
        }

        private static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        // ── Stream I/O Helpers ───────────────────────────────────────

        private static async Task SendJson<T>(Stream stream, T obj)
        {
            string json = JsonConvert.SerializeObject(obj, Protocol.JsonSettings);
            byte[] data = Encoding.UTF8.GetBytes(json + "\n");
            await stream.WriteAsync(data, 0, data.Length);
            await stream.FlushAsync();
        }

        private static async Task<JObject> ReadJson(Stream stream)
        {
            var buffer = new byte[Protocol.MAX_MESSAGE_SIZE];
            int offset = 0;

            try
            {
                while (true)
                {
                    int bytesRead = await stream.ReadAsync(buffer, offset, buffer.Length - offset);
                    if (bytesRead == 0) return null;
                    offset += bytesRead;

                    int newlinePos = Array.IndexOf(buffer, (byte)'\n', 0, offset);
                    if (newlinePos >= 0)
                    {
                        string json = Encoding.UTF8.GetString(buffer, 0, newlinePos);
                        return JObject.Parse(json);
                    }
                }
            }
            catch (IOException)
            {
                return null;
            }
        }

        private static async Task SendError(
            Stream stream, string type, string nonce,
            string errorCode, string errorMessage)
        {
            var reply = new BridgeResponse
            {
                Type = type,
                Nonce = nonce,
                Status = "error",
                ErrorCode = errorCode,
                ErrorMessage = errorMessage,
            };
            await SendJson(stream, reply);
        }
    }
}
