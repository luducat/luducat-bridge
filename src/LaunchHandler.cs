// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using Playnite.SDK;
using Playnite.SDK.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace LuducatBridge
{
    /// <summary>
    /// Resolves store+ID to Playnite game GUID and delegates launching
    /// to PlayniteApi.StartGame(). Never executes binaries directly.
    /// </summary>
    public class LaunchHandler
    {
        private readonly IPlayniteAPI _api;
        private readonly BridgeSettings _settings;
        private readonly ILogger _logger;

        // Store name → Playnite library plugin source name mapping
        private static readonly Dictionary<string, string[]> StoreSourceMap =
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "steam", new[] { "Steam", "steam" } },
            { "gog", new[] { "GOG", "gog" } },
            { "epic", new[] { "Epic", "epic", "Epic Games Store" } },
        };

        public LaunchHandler(IPlayniteAPI api, BridgeSettings settings, ILogger logger)
        {
            _api = api;
            _settings = settings;
            _logger = logger;
        }

        /// <summary>
        /// Handle a launch request from luducat.
        /// </summary>
        public JObject HandleLaunch(JObject launchMsg)
        {
            string nonce = launchMsg["nonce"]?.ToString() ?? "";
            string store = launchMsg["store"]?.ToString() ?? "";
            string storeId = launchMsg["store_id"]?.ToString() ?? "";

            _logger.Info($"Launch request: store={store}, id={storeId}");

            var game = ResolveGame(store, storeId);

            if (game == null)
            {
                _logger.Warn($"Game not found: store={store}, id={storeId}");
                return CreateLaunchResult(nonce, "not_found",
                    errorCode: ErrorCodes.GAME_NOT_FOUND,
                    errorMessage: $"No game with store={store}, store_id={storeId} in Playnite library");
            }

            if (!game.IsInstalled)
            {
                _logger.Warn($"Game not installed: {game.Id}");
                return CreateLaunchResult(nonce, "not_installed",
                    playniteId: game.Id.ToString(),
                    gameName: game.Name,
                    installed: false);
            }

            try
            {
                _api.StartGame(game.Id);

                _logger.Info($"Launch result: started (store={store}, id={storeId})");
                return CreateLaunchResult(nonce, "started",
                    playniteId: game.Id.ToString(),
                    gameName: game.Name,
                    installed: true);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Launch failed: store={store}, id={storeId}");
                return CreateLaunchResult(nonce, "failed",
                    playniteId: game.Id.ToString(),
                    gameName: game.Name,
                    installed: true,
                    errorCode: ErrorCodes.LAUNCH_FAILED,
                    errorMessage: ex.Message);
            }
        }

        public int GetGameCount()
        {
            try
            {
                return _api.Database.Games?.Count ?? 0;
            }
            catch
            {
                return 0;
            }
        }

        // ── Resolution ───────────────────────────────────────────────

        private Game ResolveGame(string store, string storeId)
        {
            string[] sourceNames;
            if (!StoreSourceMap.TryGetValue(store.ToLowerInvariant(), out sourceNames))
                return null;

            var games = _api.Database.Games;
            if (games == null) return null;

            foreach (var game in games)
            {
                string gameSource = game.Source?.Name;
                if (gameSource == null) continue;

                bool sourceMatch = sourceNames.Any(s =>
                    s.Equals(gameSource, StringComparison.OrdinalIgnoreCase));
                if (!sourceMatch) continue;

                if (string.Equals(game.GameId, storeId, StringComparison.OrdinalIgnoreCase))
                    return game;
            }

            return null;
        }

        // ── Response Construction ────────────────────────────────────

        private static JObject CreateLaunchResult(
            string nonce,
            string launchStatus,
            string playniteId = null,
            string gameName = null,
            bool? installed = null,
            string errorCode = null,
            string errorMessage = null)
        {
            var result = new LaunchResultMessage
            {
                Type = "launch_result",
                Nonce = nonce,
                Status = errorCode != null ? "error" : "ok",
                LaunchStatus = launchStatus,
                PlayniteId = playniteId,
                GameName = gameName,
                Installed = installed,
                Timestamp = DateTime.UtcNow.ToString("o"),
                ErrorCode = errorCode,
                ErrorMessage = errorMessage,
            };

            return JObject.FromObject(result,
                Newtonsoft.Json.JsonSerializer.Create(Protocol.JsonSettings));
        }
    }
}
