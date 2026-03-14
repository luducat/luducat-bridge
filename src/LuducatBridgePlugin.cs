// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using Playnite.SDK;
using Playnite.SDK.Events;
using Playnite.SDK.Plugins;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace LuducatBridge
{
    /// <summary>
    /// luducat Bridge — Playnite Generic Plugin.
    /// Listens for IPC commands from luducat and relays game launches
    /// to the Playnite SDK.
    /// </summary>
    public class LuducatBridgePlugin : GenericPlugin
    {
        private static readonly ILogger _logger = LogManager.GetLogger();
        internal static LuducatBridgePlugin Instance { get; private set; }

        private BridgeSettings _settings;
        private BridgeServer _server;
        private PairingManager _pairingManager;
        private SessionManager _sessionManager;
        private LaunchHandler _launchHandler;

        public override Guid Id
        {
            get { return Guid.Parse("d4e5f678-9012-3456-7890-abcdef123456"); }
        }

        public LuducatBridgePlugin(IPlayniteAPI api) : base(api)
        {
            Instance = this;
            Properties = new GenericPluginProperties { HasSettings = true };
            _settings = new BridgeSettings(this);
        }

        public override void OnApplicationStarted(OnApplicationStartedEventArgs args)
        {
            _launchHandler = new LaunchHandler(PlayniteApi, _settings, _logger);
            _pairingManager = new PairingManager(_settings, _logger);
            _sessionManager = new SessionManager(_pairingManager, _settings, _logger);

            // Wire settings callbacks for the settings view
            _settings.GetIsPaired = () => _pairingManager?.IsPaired ?? false;
            _settings.GetStatusText = () =>
            {
                if (_pairingManager == null) return "Not initialized";
                if (!_pairingManager.IsPaired) return "Not paired";
                if (_server?.HasActiveSession == true) return "Connected";
                return "Paired (not connected)";
            };
            _settings.OnUnpairRequested = () => { _pairingManager?.Unpair(); };

            _settings.GetHasPendingPairing = () => _pairingManager?.HasPendingPairing ?? false;
            _settings.GetPendingPeerInfo = () =>
            {
                if (_pairingManager == null || !_pairingManager.HasPendingPairing)
                    return null;
                string addr = _pairingManager.PendingPeerAddress ?? "?";
                string ver = _pairingManager.PendingPeerVersion;
                if (!string.IsNullOrEmpty(ver))
                    return $"{addr} (luducat v{ver})";
                return addr;
            };
            _settings.SubmitPairingCode = (code) => _pairingManager?.SubmitPairingCode(code);
            _settings.CancelPendingPairing = () => _pairingManager?.CancelPendingPairing();
            _settings.OnPendingPairingChanged = () => { };

            _server = new BridgeServer(
                _settings,
                _pairingManager,
                _sessionManager,
                _launchHandler,
                _logger
            );

            try
            {
                _server.Start();
                _logger.Info($"luducat bridge listening on port {_settings.Port}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to start luducat bridge server");
            }
        }

        public override void OnApplicationStopped(OnApplicationStoppedEventArgs args)
        {
            if (_server != null)
            {
                _server.Stop();
                _logger.Info("luducat bridge stopped");
            }
        }

        public override ISettings GetSettings(bool firstRunSettings)
        {
            return _settings;
        }

        public override UserControl GetSettingsView(bool firstRunView)
        {
            return new Settings.BridgeSettingsView();
        }

        public override IEnumerable<MainMenuItem> GetMainMenuItems(GetMainMenuItemsArgs args)
        {
            yield return new MainMenuItem
            {
                Description = "luducat Bridge Status",
                MenuSection = "@luducat",
                Action = (a) => ShowBridgeStatus()
            };
        }

        private void ShowBridgeStatus()
        {
            bool paired = _pairingManager != null && _pairingManager.IsPaired;
            bool connected = _server != null && _server.HasActiveSession;
            int port = _settings.Port;

            string status = paired
                ? (connected ? "Connected" : "Paired (not connected)")
                : "Not paired";

            PlayniteApi.Dialogs.ShowMessage(
                $"luducat Bridge Status\n\n" +
                $"Status: {status}\n" +
                $"Port: {port}\n" +
                $"Protocol: {Protocol.PROTOCOL_VERSION}",
                "luducat Bridge"
            );
        }

        public override void Dispose()
        {
            if (_server != null)
                _server.Stop();
            base.Dispose();
        }
    }
}
