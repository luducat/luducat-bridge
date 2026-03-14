// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace LuducatBridge.Settings
{
    /// <summary>
    /// Settings view for the luducat bridge plugin.
    /// Built programmatically since SDK-style csproj + .NET Framework XAML
    /// compilation is unreliable.
    /// </summary>
    public class BridgeSettingsView : UserControl
    {
        private TextBlock _statusBullet;
        private TextBlock _statusText;
        private Button _unpairButton;

        public BridgeSettingsView()
        {
            var stack = new StackPanel { Margin = new Thickness(20) };

            // Title
            stack.Children.Add(new TextBlock
            {
                Text = "luducat Bridge Settings",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 15),
            });

            // ── Connection group ───────────────────────────────────────
            var connGroup = new GroupBox { Header = "Connection", Margin = new Thickness(0, 0, 0, 10) };
            var connStack = new StackPanel { Margin = new Thickness(10) };

            // Status row
            var statusRow = new StackPanel { Orientation = Orientation.Horizontal };
            statusRow.Children.Add(new TextBlock
            {
                Text = "Status:",
                Width = 120,
                VerticalAlignment = VerticalAlignment.Center,
            });
            _statusBullet = new TextBlock
            {
                Text = "\u25CF ",
                VerticalAlignment = VerticalAlignment.Center,
            };
            statusRow.Children.Add(_statusBullet);
            _statusText = new TextBlock
            {
                VerticalAlignment = VerticalAlignment.Center,
            };
            statusRow.Children.Add(_statusText);
            connStack.Children.Add(statusRow);

            // Unpair button row
            var unpairRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 8, 0, 0),
            };
            _unpairButton = new Button
            {
                Content = "Unpair",
                Padding = new Thickness(16, 4, 16, 4),
            };
            _unpairButton.Click += OnUnpairClicked;
            unpairRow.Children.Add(_unpairButton);
            connStack.Children.Add(unpairRow);

            connGroup.Content = connStack;
            stack.Children.Add(connGroup);

            // ── Network group ──────────────────────────────────────────
            var portGroup = new GroupBox { Header = "Network", Margin = new Thickness(0, 0, 0, 10) };
            var portStack = new StackPanel { Margin = new Thickness(10) };
            var portRow = new StackPanel { Orientation = Orientation.Horizontal };
            portRow.Children.Add(new TextBlock
            {
                Text = "Port:",
                Width = 120,
                VerticalAlignment = VerticalAlignment.Center,
            });
            var portBox = new TextBox { Width = 100 };
            portBox.SetBinding(TextBox.TextProperty, new Binding("Port"));
            portRow.Children.Add(portBox);
            portStack.Children.Add(portRow);
            portStack.Children.Add(new TextBlock
            {
                Text = "Default: 39817. Only change if there's a port conflict.",
                FontSize = 11,
                Foreground = Brushes.Gray,
                Margin = new Thickness(120, 2, 0, 0),
            });
            portGroup.Content = portStack;
            stack.Children.Add(portGroup);

            // ── Security group ─────────────────────────────────────────
            var secGroup = new GroupBox { Header = "Security", Margin = new Thickness(0, 0, 0, 10) };
            var secStack = new StackPanel { Margin = new Thickness(10) };
            var alwaysAllowCb = new CheckBox
            {
                Content = "Always allow game launches (skip confirmation)",
                Margin = new Thickness(0, 0, 0, 5),
            };
            alwaysAllowCb.SetBinding(CheckBox.IsCheckedProperty, new Binding("AlwaysAllow"));
            secStack.Children.Add(alwaysAllowCb);
            secStack.Children.Add(new TextBlock
            {
                Text = "When unchecked, each launch request from luducat requires your confirmation.",
                FontSize = 11,
                Foreground = Brushes.Gray,
                Margin = new Thickness(20, 0, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            });
            secGroup.Content = secStack;
            stack.Children.Add(secGroup);

            // ── Data Sync group (coming soon) ──────────────────────────
            var syncGroup = new GroupBox
            {
                Header = "Data Sync (coming soon)",
                Margin = new Thickness(0, 0, 0, 10),
            };
            var syncStack = new StackPanel { Margin = new Thickness(10) };
            syncStack.Children.Add(new CheckBox
            {
                Content = "Share favorites with luducat",
                IsEnabled = false,
                Margin = new Thickness(0, 0, 0, 4),
            });
            syncStack.Children.Add(new CheckBox
            {
                Content = "Share tags with luducat",
                IsEnabled = false,
                Margin = new Thickness(0, 0, 0, 4),
            });
            syncStack.Children.Add(new CheckBox
            {
                Content = "Share playtime data with luducat",
                IsEnabled = false,
                Margin = new Thickness(0, 0, 0, 8),
            });
            syncStack.Children.Add(new TextBlock
            {
                Text = "These features are not yet available.",
                FontSize = 11,
                Foreground = Brushes.Gray,
                FontStyle = FontStyles.Italic,
            });
            syncGroup.Content = syncStack;
            stack.Children.Add(syncGroup);

            // ── Advanced group ─────────────────────────────────────────
            var advGroup = new GroupBox { Header = "Advanced", Margin = new Thickness(0, 0, 0, 10) };
            var advStack = new StackPanel { Margin = new Thickness(10) };
            var debugCb = new CheckBox { Content = "Enable debug logging" };
            debugCb.SetBinding(CheckBox.IsCheckedProperty, new Binding("DebugLogging"));
            advStack.Children.Add(debugCb);
            advGroup.Content = advStack;
            stack.Children.Add(advGroup);

            Content = stack;

            // Initial status update
            Loaded += (s, e) => RefreshStatus();
        }

        private void RefreshStatus()
        {
            var settings = DataContext as BridgeSettings;
            if (settings == null)
                return;

            bool isPaired = settings.GetIsPaired?.Invoke() ?? false;
            string statusText = settings.GetStatusText?.Invoke() ?? "Unknown";

            _statusText.Text = statusText;
            _unpairButton.IsEnabled = isPaired;

            if (string.Equals(statusText, "Connected", System.StringComparison.Ordinal))
            {
                _statusBullet.Foreground = Brushes.LimeGreen;
            }
            else if (isPaired)
            {
                _statusBullet.Foreground = Brushes.Orange;
            }
            else
            {
                _statusBullet.Foreground = Brushes.Gray;
            }
        }

        private void OnUnpairClicked(object sender, RoutedEventArgs e)
        {
            var settings = DataContext as BridgeSettings;
            if (settings?.OnUnpairRequested == null)
                return;

            var result = MessageBox.Show(
                "This will disconnect luducat and require re-pairing.\n\nContinue?",
                "Unpair",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                settings.OnUnpairRequested.Invoke();
                RefreshStatus();
            }
        }
    }
}
