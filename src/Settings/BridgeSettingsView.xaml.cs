// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace LuducatBridge.Settings
{
    /// <summary>
    /// Settings view for the luducat bridge plugin.
    /// Built programmatically since SDK-style csproj + .NET Framework XAML
    /// compilation is unreliable.
    /// </summary>
    public class BridgeSettingsView : UserControl
    {
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

            // Port setting
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
                Foreground = System.Windows.Media.Brushes.Gray,
                Margin = new Thickness(120, 2, 0, 0),
            });
            portGroup.Content = portStack;
            stack.Children.Add(portGroup);

            // Security settings
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
                Foreground = System.Windows.Media.Brushes.Gray,
                Margin = new Thickness(20, 0, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            });
            secGroup.Content = secStack;
            stack.Children.Add(secGroup);

            // Debug setting
            var advGroup = new GroupBox { Header = "Advanced", Margin = new Thickness(0, 0, 0, 10) };
            var advStack = new StackPanel { Margin = new Thickness(10) };
            var debugCb = new CheckBox { Content = "Enable debug logging" };
            debugCb.SetBinding(CheckBox.IsCheckedProperty, new Binding("DebugLogging"));
            advStack.Children.Add(debugCb);
            advGroup.Content = advStack;
            stack.Children.Add(advGroup);

            Content = stack;
        }
    }
}
