// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Collections.Generic;
using Moq;
using Newtonsoft.Json.Linq;
using Playnite.SDK;
using Playnite.SDK.Models;
using Xunit;

namespace LuducatBridge.Tests
{
    public class LaunchHandlerTests
    {
        private readonly Mock<IPlayniteAPI> _apiMock;
        private readonly Mock<IGameDatabaseAPI> _dbMock;
        private readonly Mock<ILogger> _loggerMock;
        private readonly BridgeSettings _settings;

        public LaunchHandlerTests()
        {
            _apiMock = new Mock<IPlayniteAPI>();
            _dbMock = new Mock<IGameDatabaseAPI>();
            _loggerMock = new Mock<ILogger>();
            _settings = new BridgeSettings();

            _apiMock.Setup(a => a.Database).Returns(_dbMock.Object);
        }

        private static JObject MakeLaunchMsg(string store, string storeId, string nonce = "test-nonce")
        {
            return new JObject
            {
                ["type"] = "launch",
                ["store"] = store,
                ["store_id"] = storeId,
                ["nonce"] = nonce,
            };
        }

        /// <summary>
        /// Create a LaunchHandler mock where ResolveGame is overridden
        /// to return a controlled Game object. This bypasses the Playnite
        /// database context requirement for Game.Source resolution.
        /// </summary>
        private Mock<LaunchHandler> CreateMockHandler(Game resolvedGame = null)
        {
            var mock = new Mock<LaunchHandler>(
                _apiMock.Object, _settings, _loggerMock.Object)
            {
                CallBase = true,
            };
            mock.Setup(h => h.ResolveGame(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(resolvedGame);
            return mock;
        }

        private static Game MakeGame(string gameId, bool installed = true, string name = "Test Game")
        {
            return new Game(name) { GameId = gameId, IsInstalled = installed };
        }

        // ── Game Found + Installed → started ──────────────────────────

        [Fact]
        public void HandleLaunch_GameFound_Installed_ReturnsStarted()
        {
            var game = MakeGame("440", installed: true, name: "Team Fortress 2");
            var handler = CreateMockHandler(game);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "440"));

            Assert.Equal("ok", result["status"]?.ToString());
            Assert.Equal("started", result["launch_status"]?.ToString());
            Assert.Equal("Team Fortress 2", result["game_name"]?.ToString());
            Assert.True(result["installed"]?.ToObject<bool>());
            Assert.Equal("launch_result", result["type"]?.ToString());
            _apiMock.Verify(a => a.StartGame(game.Id), Times.Once);
        }

        // ── Game Not Found ────────────────────────────────────────────

        [Fact]
        public void HandleLaunch_GameNotFound_ReturnsNotFound()
        {
            var handler = CreateMockHandler(resolvedGame: null);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "999999"));

            Assert.Equal("error", result["status"]?.ToString());
            Assert.Equal("not_found", result["launch_status"]?.ToString());
            Assert.Equal("GAME_NOT_FOUND", result["error_code"]?.ToString());
        }

        // ── Game Not Installed ────────────────────────────────────────

        [Fact]
        public void HandleLaunch_GameNotInstalled_ReturnsNotInstalled()
        {
            var game = MakeGame("440", installed: false, name: "TF2");
            var handler = CreateMockHandler(game);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "440"));

            Assert.Equal("ok", result["status"]?.ToString());
            Assert.Equal("not_installed", result["launch_status"]?.ToString());
            Assert.Equal("TF2", result["game_name"]?.ToString());
            Assert.False(result["installed"]?.ToObject<bool>());
            _apiMock.Verify(a => a.StartGame(It.IsAny<Guid>()), Times.Never);
        }

        // ── Launch Exception ──────────────────────────────────────────

        [Fact]
        public void HandleLaunch_StartGameThrows_ReturnsFailed()
        {
            var game = MakeGame("440", installed: true, name: "TF2");
            var handler = CreateMockHandler(game);
            _apiMock.Setup(a => a.StartGame(game.Id)).Throws(new Exception("Process failed"));

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "440"));

            Assert.Equal("error", result["status"]?.ToString());
            Assert.Equal("failed", result["launch_status"]?.ToString());
            Assert.Equal("LAUNCH_FAILED", result["error_code"]?.ToString());
            Assert.Contains("Process failed", result["error_message"]?.ToString());
        }

        // ── Nonce Passed Through ──────────────────────────────────────

        [Fact]
        public void HandleLaunch_NoncePassedToResult()
        {
            var handler = CreateMockHandler(resolvedGame: null);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "1", "my-nonce-42"));

            Assert.Equal("my-nonce-42", result["nonce"]?.ToString());
        }

        // ── Timestamp Present ─────────────────────────────────────────

        [Fact]
        public void HandleLaunch_ResultHasTimestamp()
        {
            var handler = CreateMockHandler(resolvedGame: null);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "1"));

            Assert.NotNull(result["timestamp"]);
            Assert.NotEmpty(result["timestamp"]?.ToString());
        }

        // ── Playnite ID Returned ──────────────────────────────────────

        [Fact]
        public void HandleLaunch_ReturnsPlayniteId()
        {
            var game = MakeGame("440", installed: true, name: "TF2");
            var handler = CreateMockHandler(game);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "440"));

            Assert.Equal(game.Id.ToString(), result["playnite_id"]?.ToString());
        }

        // ── Not Installed — Returns Playnite ID Too ───────────────────

        [Fact]
        public void HandleLaunch_NotInstalled_StillReturnsPlayniteId()
        {
            var game = MakeGame("440", installed: false, name: "TF2");
            var handler = CreateMockHandler(game);

            var result = handler.Object.HandleLaunch(MakeLaunchMsg("steam", "440"));

            Assert.Equal(game.Id.ToString(), result["playnite_id"]?.ToString());
        }

        // ── ResolveGame Store Mapping ─────────────────────────────────
        // These test the actual ResolveGame path with real IItemCollection.
        // Game.Source requires database context — so without it,
        // ResolveGame always returns null. This confirms the null-safety path.

        [Fact]
        public void ResolveGame_EmptyCollection_ReturnsNull()
        {
            var mockGames = new Mock<IItemCollection<Game>>();
            mockGames.Setup(c => c.GetEnumerator())
                .Returns(new List<Game>().GetEnumerator());
            _dbMock.Setup(d => d.Games).Returns(mockGames.Object);

            var handler = new LaunchHandler(_apiMock.Object, _settings, _loggerMock.Object);
            var game = handler.ResolveGame("steam", "440");

            Assert.Null(game);
        }

        [Fact]
        public void ResolveGame_UnknownStore_ReturnsNull()
        {
            var mockGames = new Mock<IItemCollection<Game>>();
            mockGames.Setup(c => c.GetEnumerator())
                .Returns(new List<Game>().GetEnumerator());
            _dbMock.Setup(d => d.Games).Returns(mockGames.Object);

            var handler = new LaunchHandler(_apiMock.Object, _settings, _loggerMock.Object);
            var game = handler.ResolveGame("itch", "12345");

            Assert.Null(game);
        }

        [Fact]
        public void ResolveGame_NullGamesCollection_ReturnsNull()
        {
            _dbMock.Setup(d => d.Games).Returns((IItemCollection<Game>)null);

            var handler = new LaunchHandler(_apiMock.Object, _settings, _loggerMock.Object);
            var game = handler.ResolveGame("steam", "440");

            Assert.Null(game);
        }

        // ── GetGameCount ──────────────────────────────────────────────

        [Fact]
        public void GetGameCount_ReturnsCount()
        {
            var mockGames = new Mock<IItemCollection<Game>>();
            mockGames.Setup(c => c.Count).Returns(42);
            _dbMock.Setup(d => d.Games).Returns(mockGames.Object);

            var handler = new LaunchHandler(_apiMock.Object, _settings, _loggerMock.Object);
            Assert.Equal(42, handler.GetGameCount());
        }

        [Fact]
        public void GetGameCount_NullGames_Returns0()
        {
            _dbMock.Setup(d => d.Games).Returns((IItemCollection<Game>)null);

            var handler = new LaunchHandler(_apiMock.Object, _settings, _loggerMock.Object);
            Assert.Equal(0, handler.GetGameCount());
        }

        [Fact]
        public void GetGameCount_Exception_Returns0()
        {
            _dbMock.Setup(d => d.Games).Throws(new Exception("DB error"));

            var handler = new LaunchHandler(_apiMock.Object, _settings, _loggerMock.Object);
            Assert.Equal(0, handler.GetGameCount());
        }
    }
}
