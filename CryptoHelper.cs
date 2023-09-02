using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace SQLCipherDecryptor
{
    public class CryptoHelper
    {
        // SQLCipher 3.x defaults
        const int SALT_MASK = 0x3a;
        const int KEY_SIZE = 32; // 256-bit AES-CBC
        const int KDF_ITERATIONS = 64000;
        const int HMAC_KEY_SIZE = 32;
        const int HMAC_KEY_ITER = 2;
        const int PAGE_SIZE = 1024;
        const int IV_SIZE = 16;
        const int RESERVE_SIZE = 48;
        const int HMAC_SIZE = 20;
        const string HMAC_ALGORITHM = "HMACSHA1";

        #region Sync Decrypt

        public static byte[] DecryptDefault(byte[] raw, byte[] password)
        {
            int saltMask = SALT_MASK;
            int keySize = KEY_SIZE;
            int kdfIterations = KDF_ITERATIONS;
            int hmacKeySize = HMAC_KEY_SIZE;
            int hmacKeyIterations = HMAC_KEY_ITER;
            int pageSize = PAGE_SIZE;
            int ivSize = IV_SIZE;
            int reserveSize = RESERVE_SIZE;
            int hmacSize = HMAC_SIZE;

            return Decrypt(raw, password, saltMask, keySize, kdfIterations, hmacKeySize, hmacKeyIterations, pageSize, ivSize, reserveSize, hmacSize);
        }

        public static byte[] Decrypt(byte[] raw, byte[] password, int saltMask, int keySz, int keyIter, int hmacKeySz, int hmacKeyIter, int pageSz, int ivSz, int reserveSz, int hmacSz)
        {
            try
            {
                int saltSz = 16;
                byte[] salt = new byte[saltSz];
                Array.Copy(raw, salt, saltSz);
                (byte[] key, byte[] hmacKey) = Utility.KeyDerive(salt, password, saltMask, keySz, keyIter, hmacKeySz, hmacKeyIter);

                byte[] dec = Encoding.UTF8.GetBytes("SQLite format 3\0");
                int numPages = (int)Math.Ceiling((double)raw.Length / pageSz);

                ConcurrentDictionary<int, byte[]> decryptedPages = new();
                ParallelOptions parallelOptions = new() { MaxDegreeOfParallelism = Environment.ProcessorCount * 2 };  // Increase as per testing

                Parallel.For(0, numPages, parallelOptions, i =>
                {
                    byte[] page = Utility.GetPage(raw, pageSz, i + 1);
                    if (i == 0)
                    {
                        byte[] temp = new byte[page.Length - saltSz];
                        Array.Copy(page, saltSz, temp, 0, page.Length - saltSz);
                        page = temp;
                    }

                    byte[] pageContent = new byte[page.Length - reserveSz];
                    Array.Copy(page, 0, pageContent, 0, pageContent.Length);

                    byte[] reserve = new byte[reserveSz];
                    Array.Copy(page, page.Length - reserveSz, reserve, 0, reserveSz);

                    byte[] iv = new byte[ivSz];
                    Array.Copy(reserve, 0, iv, 0, ivSz);

                    byte[] hmacOld = new byte[hmacSz];
                    Array.Copy(reserve, ivSz, hmacOld, 0, hmacSz);

                    byte[] hmacNew = Utility.GenerateHMAC(hmacKey, Utility.ConcatArrays(pageContent, iv), i + 1);

                    if (!Utility.CompareByteArrays(hmacOld, hmacNew))
                    {
                        throw new Exception($"HMAC check failed in page {i + 1}.");
                    }

                    byte[] pageDec = Utility.DecryptAES(pageContent, key, iv);
                    byte[] randomBytes = Utility.RandomBytes(reserveSz);
                    byte[] concatenated = Utility.ConcatArrays(pageDec, randomBytes);

                    decryptedPages.TryAdd(i, concatenated);
                });

                using MemoryStream ms = new(dec.Length + numPages * (pageSz + reserveSz));
                ms.Write(dec, 0, dec.Length);

                for (int i = 0; i < numPages; i++)
                {
                    if (decryptedPages.TryGetValue(i, out byte[] pageData))
                    {
                        ms.Write(pageData, 0, pageData.Length);
                    }
                }

                return ms.ToArray();
            }
            catch (Exception ex)
            {
                throw new Exception($"SQLCipher v3.0 Decryt: An error occured: {ex}.");
            }
        }

        #endregion

        #region Async Decrypt

        public static async Task<byte[]> DecryptDefaultAsync(byte[] raw, byte[] password)
        {
            int saltMask = SALT_MASK;
            int keySize = KEY_SIZE;
            int kdfIterations = KDF_ITERATIONS;
            int hmacKeySize = HMAC_KEY_SIZE;
            int hmacKeyIterations = HMAC_KEY_ITER;
            int pageSize = PAGE_SIZE;
            int ivSize = IV_SIZE;
            int reserveSize = RESERVE_SIZE;
            int hmacSize = HMAC_SIZE;

            return await DecryptAsync(raw, password, saltMask, keySize, kdfIterations, hmacKeySize, hmacKeyIterations, pageSize, ivSize, reserveSize, hmacSize);
        }

        public static async Task<byte[]> DecryptAsync(byte[] raw, byte[] password, int saltMask, int keySz, int keyIter, int hmacKeySz, int hmacKeyIter, int pageSz, int ivSz, int reserveSz, int hmacSz)
        {
            try
            {
                int saltSz = 16;
                byte[] salt = new byte[saltSz];
                Array.Copy(raw, salt, saltSz);
                (byte[] key, byte[] hmacKey) = Utility.KeyDerive(salt, password, saltMask, keySz, keyIter, hmacKeySz, hmacKeyIter);

                byte[] dec = Encoding.UTF8.GetBytes("SQLite format 3\0");
                int numPages = (int)Math.Ceiling((double)raw.Length / pageSz);

                ConcurrentDictionary<int, byte[]> decryptedPages = new();

                List<Task> tasks = new();

                for (int i = 0; i < numPages; i++)
                {
                    tasks.Add(Task.Run(() =>
                    {
                        byte[] page = Utility.GetPage(raw, pageSz, i + 1);
                        if (i == 0)
                        {
                            byte[] temp = new byte[page.Length - saltSz];
                            Array.Copy(page, saltSz, temp, 0, page.Length - saltSz);
                            page = temp;
                        }

                        byte[] pageContent = new byte[page.Length - reserveSz];
                        Array.Copy(page, 0, pageContent, 0, pageContent.Length);

                        byte[] reserve = new byte[reserveSz];
                        Array.Copy(page, page.Length - reserveSz, reserve, 0, reserveSz);

                        byte[] iv = new byte[ivSz];
                        Array.Copy(reserve, 0, iv, 0, ivSz);

                        byte[] hmacOld = new byte[hmacSz];
                        Array.Copy(reserve, ivSz, hmacOld, 0, hmacSz);

                        byte[] hmacNew = Utility.GenerateHMAC(hmacKey, Utility.ConcatArrays(pageContent, iv), i + 1);

                        if (!Utility.CompareByteArrays(hmacOld, hmacNew))
                        {
                            throw new Exception($"HMAC check failed in page {i + 1}.");
                        }

                        byte[] pageDec = Utility.DecryptAES(pageContent, key, iv);
                        byte[] randomBytes = Utility.RandomBytes(reserveSz);
                        byte[] concatenated = Utility.ConcatArrays(pageDec, randomBytes);

                        decryptedPages.TryAdd(i, concatenated);
                    }));
                }

                await Task.WhenAll(tasks);

                using MemoryStream ms = new(dec.Length + numPages * (pageSz + reserveSz));
                await ms.WriteAsync(dec.AsMemory(0, dec.Length));

                for (int i = 0; i < numPages; i++)
                {
                    if (decryptedPages.TryGetValue(i, out byte[] pageData))
                    {
                        await ms.WriteAsync(pageData.AsMemory(0, pageData.Length));
                    }
                }

                return ms.ToArray();
            }
            catch (Exception ex)
            {
                throw new Exception($"SQLCipher v3.0 Decryt: An error occured: {ex}.");
            }
        }

        #endregion

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

            if (!Utility.CompareByteArrays(computedHmac, storedHmac))
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

        public static (int, int) DecryptPageHeader(byte[] raw, byte[] key, int saltSz, int pageSz, int ivSz, int reserveSz)
        {
            if (!Utility.IsValidPageSize(pageSz))
            {
                pageSz = 512;
            }

            int newReserveSz = TryGetReserveSizeForSpecifiedPageSize(raw, key, saltSz, pageSz, ivSz, reserveSz);
            if (newReserveSz > 0)
            {
                return (pageSz, newReserveSz);
            }

            pageSz = 512;
            while (pageSz <= 65536)
            {
                newReserveSz = TryGetReserveSizeForSpecifiedPageSize(raw, key, saltSz, pageSz, ivSz, reserveSz);
                if (newReserveSz > 0)
                {
                    return (pageSz, newReserveSz);
                }
                pageSz <<= 1;
            }

            return (-1, -1);
        }

        public static int TryGetReserveSizeForSpecifiedPageSize(byte[] raw, byte[] key, int saltSz, int pageSz, int ivSz, int reserveSz)
        {
            byte[] firstPageContent = Utility.GetPage(raw, pageSz, 1).Skip(saltSz).ToArray();

            if (reserveSz >= ivSz)
            {
                byte[] firstPageDec = DecryptByReserveSize(firstPageContent, key, ivSz, reserveSz);
                if (Utility.IsValidDecryptedHeader(firstPageDec)
                    && pageSz == Utility.GetPageSizeFromDatabaseHeader(Utility.ConcatArrays(raw.Take(saltSz).ToArray(), firstPageDec))
                    && reserveSz == Utility.GetReservedSizeFromDatabaseHeader(Utility.ConcatArrays(raw.Take(saltSz).ToArray(), firstPageDec)))
                {
                    return reserveSz;
                }
            }

            for (reserveSz = ivSz; reserveSz < pageSz - 480; reserveSz++)
            {
                byte[] firstPageDec = DecryptByReserveSize(firstPageContent, key, ivSz, reserveSz);
                if (Utility.IsValidDecryptedHeader(firstPageDec)
                    && pageSz == Utility.GetPageSizeFromDatabaseHeader(Utility.ConcatArrays(raw.Take(saltSz).ToArray(), firstPageDec))
                    && reserveSz == Utility.GetReservedSizeFromDatabaseHeader(Utility.ConcatArrays(raw.Take(saltSz).ToArray(), firstPageDec)))
                {
                    return reserveSz;
                }
            }

            return -1;
        }

        public static byte[] DecryptByReserveSize(byte[] firstPageWithoutSalt, byte[] key, int ivSz, int reserveSz)
        {
            byte[] reserve = firstPageWithoutSalt.Skip(firstPageWithoutSalt.Length - reserveSz).ToArray();
            byte[] iv = reserve.Take(ivSz).ToArray();
            return Utility.DecryptAES(firstPageWithoutSalt, key, iv);
        }
    }
}
