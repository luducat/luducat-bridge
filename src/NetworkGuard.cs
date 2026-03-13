// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System.Net;
using System.Net.Sockets;

namespace LuducatBridge
{
    /// <summary>
    /// Enforces RFC 1918 private address restrictions at the socket level.
    /// All connections from non-private IPs are rejected before any
    /// protocol exchange occurs.
    /// </summary>
    public static class NetworkGuard
    {
        /// <summary>
        /// Check if an IP address is in RFC 1918 private ranges or loopback.
        /// </summary>
        public static bool IsPrivateAddress(IPAddress address)
        {
            // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] bytes = address.GetAddressBytes();
                // Check for ::ffff: prefix (IPv4-mapped IPv6)
                bool isMapped = true;
                for (int i = 0; i < 10; i++)
                    if (bytes[i] != 0) { isMapped = false; break; }
                if (isMapped && bytes[10] == 0xFF && bytes[11] == 0xFF)
                {
                    address = new IPAddress(new byte[] { bytes[12], bytes[13], bytes[14], bytes[15] });
                }
            }

            // IPv6 loopback
            if (IPAddress.IPv6Loopback.Equals(address))
                return true;

            // IPv6 link-local (fe80::/10)
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] bytes = address.GetAddressBytes();
                return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
            }

            // IPv4 checks
            if (address.AddressFamily != AddressFamily.InterNetwork)
                return false;

            byte[] addrBytes = address.GetAddressBytes();

            // 127.0.0.0/8
            if (addrBytes[0] == 127) return true;
            // 10.0.0.0/8
            if (addrBytes[0] == 10) return true;
            // 172.16.0.0/12
            if (addrBytes[0] == 172 && addrBytes[1] >= 16 && addrBytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (addrBytes[0] == 192 && addrBytes[1] == 168) return true;

            return false;
        }

        /// <summary>
        /// Validate an endpoint. Returns true if the remote IP is private.
        /// </summary>
        public static bool ValidateEndpoint(EndPoint endpoint)
        {
            var ipEndpoint = endpoint as IPEndPoint;
            if (ipEndpoint != null)
            {
                return IsPrivateAddress(ipEndpoint.Address);
            }
            return false;
        }
    }
}
