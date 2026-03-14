// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using Playnite.SDK;
using Playnite.SDK.Plugins;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace LuducatBridge
{
    /// <summary>
    /// Bridge plugin settings — configurable via Playnite's settings UI.
    /// </summary>
    public class BridgeSettings : ISettings
    {
        private readonly Plugin _plugin;

        /// <summary>TCP port the bridge listens on.</summary>
        public int Port { get; set; } = Protocol.DEFAULT_PORT;

        /// <summary>Skip one-time launch confirmation dialogs.</summary>
        public bool AlwaysAllow { get; set; } = false;

        /// <summary>Enable verbose logging.</summary>
        public bool DebugLogging { get; set; } = false;

        // Phase 2 data sync settings (persisted but not yet active)
        public bool ShareFavorites { get; set; } = false;
        public bool ShareTags { get; set; } = false;
        public bool SharePlaytime { get; set; } = false;

        // Runtime-only callbacks for settings view to access plugin state
        [JsonIgnore]
        public System.Action OnUnpairRequested { get; set; }

        [JsonIgnore]
        public System.Func<string> GetStatusText { get; set; }

        [JsonIgnore]
        public System.Func<bool> GetIsPaired { get; set; }

        public BridgeSettings() { _plugin = null; }

        public BridgeSettings(Plugin plugin)
        {
            _plugin = plugin;

            var saved = plugin.LoadPluginSettings<BridgeSettings>();
            if (saved != null)
            {
                Port = saved.Port;
                AlwaysAllow = saved.AlwaysAllow;
                DebugLogging = saved.DebugLogging;
                ShareFavorites = saved.ShareFavorites;
                ShareTags = saved.ShareTags;
                SharePlaytime = saved.SharePlaytime;
            }
        }

        public void BeginEdit() { }

        public void CancelEdit() { }

        public void EndEdit()
        {
            // Save only serializable fields — avoid self-referencing loop from
            // runtime callbacks that capture plugin references.
            var dto = new BridgeSettings
            {
                Port = Port,
                AlwaysAllow = AlwaysAllow,
                DebugLogging = DebugLogging,
                ShareFavorites = ShareFavorites,
                ShareTags = ShareTags,
                SharePlaytime = SharePlaytime,
            };
            _plugin.SavePluginSettings(dto);
        }

        public bool VerifySettings(out List<string> errors)
        {
            errors = new List<string>();

            if (Port < 1024 || Port > 65535)
            {
                errors.Add("Port must be between 1024 and 65535");
            }

            return errors.Count == 0;
        }
    }
}
