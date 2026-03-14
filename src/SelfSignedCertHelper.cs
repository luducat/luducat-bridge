// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LuducatBridge
{
    /// <summary>
    /// Self-signed certificate generation for .NET Framework 4.6.2.
    /// Uses Windows CryptAPI (CertCreateSelfSignCertificate) since
    /// CertificateRequest is only available in .NET Core 2.0+.
    /// </summary>
    internal static class SelfSignedCertHelper
    {
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertCreateSelfSignCertificate(
            IntPtr hCryptProvOrNCryptKey,
            ref CRYPT_DATA_BLOB pSubjectIssuerBlob,
            uint dwFlags,
            ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
            IntPtr pSignatureAlgorithm,
            ref SYSTEMTIME pStartTime,
            ref SYSTEMTIME pEndTime,
            IntPtr pExtensions);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertStrToNameW(
            uint dwCertEncodingType,
            string pszX500,
            uint dwStrType,
            IntPtr pvReserved,
            byte[] pbEncoded,
            ref uint pcbEncoded,
            IntPtr ppszError);

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CRYPT_KEY_PROV_INFO
        {
            public string pwszContainerName;
            public string pwszProvName;
            public uint dwProvType;
            public uint dwFlags;
            public uint cProvParam;
            public IntPtr rgProvParam;
            public uint dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEMTIME
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliseconds;

            public static SYSTEMTIME FromDateTime(DateTime dt)
            {
                return new SYSTEMTIME
                {
                    wYear = (ushort)dt.Year,
                    wMonth = (ushort)dt.Month,
                    wDay = (ushort)dt.Day,
                    wHour = (ushort)dt.Hour,
                    wMinute = (ushort)dt.Minute,
                    wSecond = (ushort)dt.Second,
                };
            }
        }

        private const uint X509_ASN_ENCODING = 0x00000001;
        private const uint CERT_X500_NAME_STR = 3;
        private const uint PROV_RSA_FULL = 1;
        private const uint PROV_RSA_AES = 24;
        private const uint AT_KEYEXCHANGE = 1;

        // Provider configurations to try in order (modern → legacy)
        private static readonly ProviderConfig[] Providers = new[]
        {
            new ProviderConfig("Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES),
            new ProviderConfig("Microsoft Strong Cryptographic Provider", PROV_RSA_FULL),
            new ProviderConfig(null, PROV_RSA_FULL),
        };

        private struct ProviderConfig
        {
            public string Name;
            public uint Type;
            public ProviderConfig(string name, uint type) { Name = name; Type = type; }
        }

        public static X509Certificate2 CreateSelfSigned(string subjectName)
        {
            // Encode subject name
            uint encodedSize = 0;
            CertStrToNameW(X509_ASN_ENCODING, subjectName, CERT_X500_NAME_STR,
                IntPtr.Zero, null, ref encodedSize, IntPtr.Zero);

            byte[] encodedName = new byte[encodedSize];
            CertStrToNameW(X509_ASN_ENCODING, subjectName, CERT_X500_NAME_STR,
                IntPtr.Zero, encodedName, ref encodedSize, IntPtr.Zero);

            var nameBlob = new CRYPT_DATA_BLOB();
            nameBlob.cbData = encodedSize;

            var startTime = SYSTEMTIME.FromDateTime(DateTime.UtcNow);
            var endTime = SYSTEMTIME.FromDateTime(DateTime.UtcNow.AddYears(10));

            IntPtr namePtr = Marshal.AllocHGlobal(encodedName.Length);
            try
            {
                Marshal.Copy(encodedName, 0, namePtr, encodedName.Length);
                nameBlob.pbData = namePtr;

                // Try each provider: pre-create exportable RSA key via managed
                // RSACryptoServiceProvider, then CertCreateSelfSignCertificate
                // reuses the existing key in the named container.
                Exception lastError = null;
                foreach (var prov in Providers)
                {
                    try
                    {
                        string containerName = "luducat-bridge-" + Guid.NewGuid().ToString("N");

                        // Pre-create exportable RSA key in named container
                        var cspParams = new CspParameters(
                            (int)prov.Type,
                            prov.Name)
                        {
                            KeyContainerName = containerName,
                            KeyNumber = (int)AT_KEYEXCHANGE,
                        };
                        using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
                        {
                            rsa.PersistKeyInCsp = true;
                        }

                        var keyProvInfo = new CRYPT_KEY_PROV_INFO
                        {
                            pwszContainerName = containerName,
                            pwszProvName = prov.Name,
                            dwProvType = prov.Type,
                            dwFlags = 0,
                            cProvParam = 0,
                            rgProvParam = IntPtr.Zero,
                            dwKeySpec = AT_KEYEXCHANGE,
                        };

                        IntPtr certContext = CertCreateSelfSignCertificate(
                            IntPtr.Zero,
                            ref nameBlob,
                            0,
                            ref keyProvInfo,
                            IntPtr.Zero,
                            ref startTime,
                            ref endTime,
                            IntPtr.Zero);

                        if (certContext != IntPtr.Zero)
                        {
                            var cert = new X509Certificate2(certContext);
                            CertFreeCertificateContext(certContext);

                            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, "luducat-bridge");
                            return new X509Certificate2(pfxBytes, "luducat-bridge",
                                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                        }

                        int error = Marshal.GetLastWin32Error();
                        lastError = new System.ComponentModel.Win32Exception(error,
                            $"CertCreateSelfSignCertificate failed with provider " +
                            $"'{prov.Name ?? "(default)"}' type={prov.Type}: 0x{error:X8}");
                    }
                    catch (Exception ex)
                    {
                        lastError = ex;
                    }
                }

                throw lastError ?? new InvalidOperationException(
                    "All certificate provider configurations failed");
            }
            finally
            {
                Marshal.FreeHGlobal(namePtr);
            }
        }
    }
}
