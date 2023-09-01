using System.Security.Cryptography;

namespace SQLCipherDecryptor
{
    public class CryptoHelper
    {
        // SQLCipher 3.x defaults
        const int PAGE_SIZE = 1024;
        const int KDF_ITERATIONS = 64000;
        const int KEY_LENGTH = 32; // 256-bit AES
        const string HMAC_ALGORITHM = "HMACSHA1";
        const string KDF_ALGORITHM = "HMACSHA1";
        const int PLAINTEXT_HEADER_SIZE = 0;

        public static byte[] DecryptPage(byte[] encryptedPage, byte[] encryptionKey, byte[] hmacKey, int pageNum)
        {
            byte[] iv = new byte[16];
            Array.Copy(encryptedPage, encryptedPage.Length - 16, iv, 0, 16);

            HMAC hmac = HMAC.Create(HMAC_ALGORITHM);
            hmac.Key = hmacKey;

            byte[] computedHmac = hmac.ComputeHash(encryptedPage, 0, encryptedPage.Length - 20);

            // Verify HMAC
            byte[] storedHmac = new byte[20];
            Array.Copy(encryptedPage, encryptedPage.Length - 20, storedHmac, 0, 20);

            if (!CompareByteArrays(computedHmac, storedHmac))
            {
                throw new InvalidOperationException($"HMAC verification failed for page {pageNum}.");
            }

            // Decrypt
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = 256;
            aes.Padding = PaddingMode.None;
            aes.Key = encryptionKey;
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor();

            byte[] decryptedPage = new byte[PAGE_SIZE];
            using (MemoryStream msDecrypt = new(encryptedPage, 0, PAGE_SIZE))
            {
                using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
                csDecrypt.Read(decryptedPage, 0, decryptedPage.Length);
            }

            return decryptedPage;
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
    }
}
