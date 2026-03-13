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

        // Non-serialized runtime state
        [JsonIgnore]
        public bool IsPaired { get; set; } = false;

        [JsonIgnore]
        public string ConnectionStatus { get; set; } = "Not connected";

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
            }
        }

        public void BeginEdit() { }

        public void CancelEdit() { }

        public void EndEdit()
        {
            _plugin.SavePluginSettings(this);
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
