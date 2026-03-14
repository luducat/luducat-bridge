// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using Playnite.SDK;
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace LuducatBridge
{
    /// <summary>
    /// TCP+TLS listener that accepts connections from luducat.
    /// All communication is over TLS — no raw TCP fallback.
    ///
    /// Connection flow:
    /// 1. TCP accept → RFC 1918 check → TLS handshake
    /// 2. Read first message type:
    ///    - "pair_hello" → pairing handshake
    ///    - "auth" → HMAC-TOTP session authentication
    /// </summary>
    public class BridgeServer : IDisposable
    {
        private readonly BridgeSettings _settings;
        private readonly PairingManager _pairing;
        private readonly SessionManager _session;
        private readonly LaunchHandler _launcher;
        private readonly ILogger _logger;

        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private Task _listenTask;
        private SslStream _activeSession;
        private readonly object _streamLock = new object();
        private volatile bool _running;

        public bool HasActiveSession
        {
            get { lock (_streamLock) { return _activeSession != null; } }
        }

        public BridgeServer(
            BridgeSettings settings,
            PairingManager pairing,
            SessionManager session,
            LaunchHandler launcher,
            ILogger logger)
        {
            _settings = settings;
            _pairing = pairing;
            _session = session;
            _launcher = launcher;
            _logger = logger;
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _running = true;
            _listener = new TcpListener(IPAddress.Any, _settings.Port);
            _listener.Start();
            _listenTask = Task.Run(() => AcceptLoop());
        }

        public void Stop()
        {
            _running = false;
            _cts?.Cancel();
            _listener?.Stop();

            lock (_streamLock)
            {
                if (_activeSession != null)
                {
                    try { _activeSession.Close(); } catch { }
                    _activeSession = null;
                }
            }

            try
            {
                if (_listenTask != null)
                    _listenTask.Wait(TimeSpan.FromSeconds(5));
            }
            catch (AggregateException) { }
        }

        private async Task AcceptLoop()
        {
            while (_running)
            {
                TcpClient client = null;
                try
                {
                    client = await _listener.AcceptTcpClientAsync();

                    // RFC 1918 enforcement at socket level
                    if (!NetworkGuard.ValidateEndpoint(client.Client.RemoteEndPoint))
                    {
                        _logger.Warn($"Rejected non-private connection from {client.Client.RemoteEndPoint}");
                        client.Close();
                        continue;
                    }

                    _logger.Info($"Accepted connection from {client.Client.RemoteEndPoint}");
                    await HandleClient(client);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException) when (!_running)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error in accept loop");
                    if (client != null)
                        try { client.Close(); } catch { }
                }
            }
        }

        private async Task HandleClient(TcpClient client)
        {
            // All connections require TLS
            var cert = _pairing.GetOrCreateServerCertificate();
            if (cert == null)
            {
                _logger.Error("No server certificate available");
                client.Close();
                return;
            }

            var sslStream = new SslStream(client.GetStream(), false);
            try
            {
                sslStream.AuthenticateAsServer(
                    cert,
                    clientCertificateRequired: false,
                    enabledSslProtocols: SslProtocols.Tls12,
                    checkCertificateRevocation: false
                );
            }
            catch (AuthenticationException ex)
            {
                _logger.Error(ex, "TLS handshake failed");
                client.Close();
                return;
            }

            _logger.Info($"TLS established: {sslStream.SslProtocol}, {sslStream.CipherAlgorithm}");

            // Read first message to determine pairing vs authenticated session
            var firstMsg = await ReadMessage(sslStream);
            if (firstMsg == null)
            {
                sslStream.Close();
                client.Close();
                return;
            }

            string msgType = firstMsg["type"]?.ToString() ?? "";

            if (msgType == "pair_hello")
            {
                try
                {
                    await _pairing.HandlePairHello(sslStream, firstMsg, cert);
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Pairing session failed");
                }
                sslStream.Close();
                client.Close();
            }
            else if (msgType == "auth")
            {
                if (!_session.ValidateAuth(firstMsg))
                {
                    string nonce = firstMsg["nonce"]?.ToString() ?? "";
                    await WriteMessage(sslStream,
                        CreateErrorResponse("auth_reply", nonce,
                            ErrorCodes.AUTH_FAILED, "TOTP verification failed"));
                    sslStream.Close();
                    client.Close();
                    return;
                }

                // Send auth reply with our TOTP for mutual verification
                string authNonce = firstMsg["nonce"]?.ToString() ?? "";
                var authReply = new AuthReply
                {
                    Type = "auth_reply",
                    Nonce = authNonce,
                    Totp = _session.ComputeCurrentTotp(),
                };
                await WriteMessage(sslStream,
                    JObject.FromObject(authReply, JsonSerializer.Create(Protocol.JsonSettings)));

                lock (_streamLock)
                {
                    if (_activeSession != null)
                        try { _activeSession.Close(); } catch { }
                    _activeSession = sslStream;
                }

                await SessionLoop(sslStream);

                lock (_streamLock)
                {
                    _activeSession = null;
                }

                sslStream.Close();
                client.Close();
            }
            else
            {
                _logger.Warn($"Unexpected first message type: {msgType}");
                sslStream.Close();
                client.Close();
            }
        }

        private async Task SessionLoop(Stream stream)
        {
            _logger.Info("Authenticated session established");

            while (_running)
            {
                var msg = await ReadMessage(stream);
                if (msg == null)
                {
                    _logger.Info("Session ended (peer disconnected or timeout)");
                    break;
                }

                string msgType = msg["type"]?.ToString() ?? "";
                string nonce = msg["nonce"]?.ToString() ?? "";

                switch (msgType)
                {
                    case "ping":
                        await WriteMessage(stream, CreateSimpleResponse("pong", nonce));
                        break;

                    case "launch":
                        var launchResult = _launcher.HandleLaunch(msg);
                        await WriteMessage(stream, launchResult);
                        break;

                    case "status":
                        var statusReply = CreateStatusReply(nonce);
                        await WriteMessage(stream, statusReply);
                        break;

                    case "disconnect":
                        _logger.Info("Client requested disconnect");
                        return;

                    case "unpair":
                        _logger.Info("Client requested unpair");
                        _pairing.Unpair();
                        return;

                    default:
                        await WriteMessage(stream,
                            CreateErrorResponse($"{msgType}_reply", nonce,
                                ErrorCodes.PROTOCOL_ERROR,
                                $"Unknown message type: {msgType}"));
                        break;
                }
            }
        }

        // ── Message I/O ──────────────────────────────────────────────

        private async Task<JObject> ReadMessage(Stream stream)
        {
            var buffer = new byte[Protocol.MAX_MESSAGE_SIZE];
            int offset = 0;

            try
            {
                while (true)
                {
                    int bytesRead = await stream.ReadAsync(buffer, offset, buffer.Length - offset);
                    if (bytesRead == 0)
                        return null;

                    offset += bytesRead;

                    int newlinePos = Array.IndexOf(buffer, (byte)'\n', 0, offset);
                    if (newlinePos >= 0)
                    {
                        string json = Encoding.UTF8.GetString(buffer, 0, newlinePos);
                        return JObject.Parse(json);
                    }

                    if (offset >= buffer.Length)
                    {
                        _logger.Error("Message exceeds maximum size");
                        return null;
                    }
                }
            }
            catch (IOException)
            {
                return null;
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
        }

        private async Task WriteMessage(Stream stream, JObject message)
        {
            string json = message.ToString(Formatting.None);
            byte[] data = Encoding.UTF8.GetBytes(json + "\n");
            await stream.WriteAsync(data, 0, data.Length);
            await stream.FlushAsync();
        }

        // ── Response Helpers ─────────────────────────────────────────

        private JObject CreateSimpleResponse(string type, string nonce)
        {
            return JObject.FromObject(new BridgeResponse { Type = type, Nonce = nonce },
                JsonSerializer.Create(Protocol.JsonSettings));
        }

        private JObject CreateErrorResponse(
            string type, string nonce, string errorCode, string errorMessage)
        {
            return JObject.FromObject(new BridgeResponse
            {
                Type = type,
                Nonce = nonce,
                Status = "error",
                ErrorCode = errorCode,
                ErrorMessage = errorMessage,
            }, JsonSerializer.Create(Protocol.JsonSettings));
        }

        private JObject CreateStatusReply(string nonce)
        {
            return JObject.FromObject(new StatusReply
            {
                Type = "status_reply",
                Nonce = nonce,
                GrantedPermissions = _pairing.GrantedPermissions,
                GameCount = _launcher.GetGameCount(),
            }, JsonSerializer.Create(Protocol.JsonSettings));
        }

        public void Dispose()
        {
            Stop();
            if (_cts != null)
                _cts.Dispose();
        }
    }
}
