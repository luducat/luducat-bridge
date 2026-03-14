// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Net;
using System.Net.Sockets;
using Xunit;

namespace LuducatBridge.Tests
{
    public class NetworkGuardTests
    {
        // ── IPv4 Private Ranges ───────────────────────────────────────

        [Theory]
        [InlineData("127.0.0.1")]
        [InlineData("127.255.255.255")]
        [InlineData("10.0.0.1")]
        [InlineData("10.255.255.255")]
        [InlineData("172.16.0.1")]
        [InlineData("172.31.255.255")]
        [InlineData("192.168.0.1")]
        [InlineData("192.168.255.255")]
        public void IsPrivateAddress_AcceptsPrivateIPv4(string addr)
        {
            Assert.True(NetworkGuard.IsPrivateAddress(IPAddress.Parse(addr)));
        }

        [Theory]
        [InlineData("8.8.8.8")]
        [InlineData("1.1.1.1")]
        [InlineData("172.32.0.1")]
        [InlineData("172.15.255.255")]
        [InlineData("192.167.1.1")]
        [InlineData("11.0.0.1")]
        [InlineData("100.64.0.1")]
        public void IsPrivateAddress_RejectsPublicIPv4(string addr)
        {
            Assert.False(NetworkGuard.IsPrivateAddress(IPAddress.Parse(addr)));
        }

        // ── IPv6 ──────────────────────────────────────────────────────

        [Fact]
        public void IsPrivateAddress_AcceptsIPv6Loopback()
        {
            Assert.True(NetworkGuard.IsPrivateAddress(IPAddress.IPv6Loopback));
        }

        [Fact]
        public void IsPrivateAddress_AcceptsIPv6LinkLocal()
        {
            Assert.True(NetworkGuard.IsPrivateAddress(IPAddress.Parse("fe80::1")));
        }

        [Fact]
        public void IsPrivateAddress_AcceptsIPv4MappedIPv6_Private()
        {
            // ::ffff:192.168.1.1
            Assert.True(NetworkGuard.IsPrivateAddress(
                IPAddress.Parse("::ffff:192.168.1.1")));
        }

        [Fact]
        public void IsPrivateAddress_RejectsIPv4MappedIPv6_Public()
        {
            // ::ffff:8.8.8.8
            Assert.False(NetworkGuard.IsPrivateAddress(
                IPAddress.Parse("::ffff:8.8.8.8")));
        }

        [Fact]
        public void IsPrivateAddress_RejectsPublicIPv6()
        {
            // 2001:db8::1 is documentation range but not private/loopback/link-local
            Assert.False(NetworkGuard.IsPrivateAddress(
                IPAddress.Parse("2001:db8::1")));
        }

        // ── Endpoint Validation ───────────────────────────────────────

        [Fact]
        public void ValidateEndpoint_AcceptsPrivateEndpoint()
        {
            var ep = new IPEndPoint(IPAddress.Parse("192.168.1.100"), 39817);
            Assert.True(NetworkGuard.ValidateEndpoint(ep));
        }

        [Fact]
        public void ValidateEndpoint_RejectsPublicEndpoint()
        {
            var ep = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 39817);
            Assert.False(NetworkGuard.ValidateEndpoint(ep));
        }

        [Fact]
        public void ValidateEndpoint_RejectsNullEndpoint()
        {
            Assert.False(NetworkGuard.ValidateEndpoint(null));
        }

        // ── Edge Cases ────────────────────────────────────────────────

        [Fact]
        public void IsPrivateAddress_Loopback127_0_0_0()
        {
            Assert.True(NetworkGuard.IsPrivateAddress(IPAddress.Parse("127.0.0.0")));
        }

        [Fact]
        public void IsPrivateAddress_10_0_0_0()
        {
            Assert.True(NetworkGuard.IsPrivateAddress(IPAddress.Parse("10.0.0.0")));
        }

        [Fact]
        public void IsPrivateAddress_BoundaryBelow172Range()
        {
            Assert.False(NetworkGuard.IsPrivateAddress(IPAddress.Parse("172.15.255.255")));
        }

        [Fact]
        public void IsPrivateAddress_BoundaryAbove172Range()
        {
            Assert.False(NetworkGuard.IsPrivateAddress(IPAddress.Parse("172.32.0.0")));
        }
    }
}
