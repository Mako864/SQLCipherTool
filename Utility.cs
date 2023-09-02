using System.Security.Cryptography;

namespace SQLCipher3Simple
{
    internal class Utility
    {
        public static byte[] DecryptAES(byte[] raw, byte[] key, byte[] iv)
        {
            try
            {
                Aes aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.KeySize = 256; // 256-bit AES
                aes.Padding = PaddingMode.None; // No padding
                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor();

                byte[] decryptedData;
                using (MemoryStream msDecrypt = new(raw))
                {
                    using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
                    using MemoryStream ms = new();
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        ms.Write(buffer, 0, bytesRead);
                    }
                    decryptedData = ms.ToArray();
                }
                return decryptedData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Utility.Decrypt: An error occurred: {ex}");
                throw; // Re-throw the exception for higher-level handling
            }
        }

        public static int GetPageSizeFromDatabaseHeader(byte[] header)
        {
            int pageSz = (256 * header[16]) + header[17];
            if (pageSz == 1)
            {
                pageSz = 65536;
            }
            return pageSz;
        }

        public static int GetReservedSizeFromDatabaseHeader(byte[] header)
        {
            return header[20];
        }

        public static bool IsValidPageSize(int pageSz)
        {
            return pageSz >= 512 && pageSz == (int)Math.Pow(2, (int)Math.Log(pageSz, 2));
        }

        public static byte[] GetPage(byte[] raw, int pageSz, int pageNo)
        {
            return raw.Skip(pageSz * (pageNo - 1)).Take(pageSz).ToArray();
        }

        public static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsValidDecryptedHeader(byte[] header)
        {
            // Skip the first 16 bytes and validate
            return header[21 - 16] == 64 && header[22 - 16] == 32 && header[23 - 16] == 32;
        }

        public static byte[] ConcatArrays(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }

        public static (byte[], byte[]) KeyDerive(byte[] salt, byte[] password, int saltMask, int keySz, int keyIter, int hmacKeySz, int hmacKeyIter)
        {
            // Derive the encryption key
            using Rfc2898DeriveBytes pbkdf2 = new(password, salt, keyIter, HashAlgorithmName.SHA1);
            byte[] key = pbkdf2.GetBytes(keySz);

            // XOR the salt with saltMask to create HMAC salt
            byte[] hmacSalt = new byte[salt.Length];
            for (int i = 0; i < salt.Length; i++)
            {
                hmacSalt[i] = (byte)(salt[i] ^ saltMask);
            }

            // Derive the HMAC key
            byte[] hmacKey;
            using (Rfc2898DeriveBytes pbkdf2Hmac = new(key, hmacSalt, hmacKeyIter, HashAlgorithmName.SHA1))
            {
                hmacKey = pbkdf2Hmac.GetBytes(hmacKeySz);
            }

            return (key, hmacKey);
        }

        public static byte[] GenerateHMAC(byte[] hmacKey, byte[] content, int pageNo)
        {
            using HMACSHA1 hmac = new(hmacKey);
            byte[] pageNoBytes = BitConverter.GetBytes((uint)pageNo);  // Convert to unsigned int
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(pageNoBytes);
            }

            byte[] combinedContent = new byte[content.Length + pageNoBytes.Length];
            Buffer.BlockCopy(content, 0, combinedContent, 0, content.Length);
            Buffer.BlockCopy(pageNoBytes, 0, combinedContent, content.Length, pageNoBytes.Length);

            return hmac.ComputeHash(combinedContent);
        }

        public static byte[] RandomBytes(int n)
        {
            byte[] randomBytes = new byte[n];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}
