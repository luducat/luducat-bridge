// This file is part of luducat-bridge. License: MIT. Contact: luducat@trinity2k.net

using System;
using System.Runtime.InteropServices;
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

        [DllImport("crypt32.dll", SetLastError = true)]
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
        private const uint CRYPT_EXPORTABLE = 0x00000001;
        private const uint AT_KEYEXCHANGE = 1;

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

            string containerName = "luducat-bridge-" + Guid.NewGuid().ToString("N");

            var keyProvInfo = new CRYPT_KEY_PROV_INFO
            {
                pwszContainerName = containerName,
                pwszProvName = null,
                dwProvType = PROV_RSA_FULL,
                dwFlags = CRYPT_EXPORTABLE,
                cProvParam = 0,
                rgProvParam = IntPtr.Zero,
                dwKeySpec = AT_KEYEXCHANGE,
            };

            var startTime = SYSTEMTIME.FromDateTime(DateTime.UtcNow);
            var endTime = SYSTEMTIME.FromDateTime(DateTime.UtcNow.AddYears(10));

            IntPtr namePtr = Marshal.AllocHGlobal(encodedName.Length);
            try
            {
                Marshal.Copy(encodedName, 0, namePtr, encodedName.Length);
                nameBlob.pbData = namePtr;

                IntPtr certContext = CertCreateSelfSignCertificate(
                    IntPtr.Zero,
                    ref nameBlob,
                    0,
                    ref keyProvInfo,
                    IntPtr.Zero,
                    ref startTime,
                    ref endTime,
                    IntPtr.Zero);

                if (certContext == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(error,
                        $"CertCreateSelfSignCertificate failed: 0x{error:X8}");
                }

                var cert = new X509Certificate2(certContext);
                CertFreeCertificateContext(certContext);

                // Re-import with exportable private key
                byte[] pfxBytes = cert.Export(X509ContentType.Pfx, "luducat-bridge");
                return new X509Certificate2(pfxBytes, "luducat-bridge",
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }
            finally
            {
                Marshal.FreeHGlobal(namePtr);
            }
        }
    }
}
