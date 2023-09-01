using System.Security.Cryptography;

namespace SQLCipherDecryptor
{
    class Program
    {
        public static async Task Decrypt(string inputFilePath, string outputFilePath, string password)
        {
            byte[] salt = new byte[16];
            byte[] encryptionKey = new byte[32];
            byte[] hmacKey = new byte[20];

            // Read salt and derive keys
            using (FileStream fs = new(inputFilePath, FileMode.Open, FileAccess.Read))
            {
                fs.Seek(16, SeekOrigin.Begin);
                fs.Read(salt, 0, 16);
            }

            using (Rfc2898DeriveBytes pbkdf2 = new(System.Text.Encoding.UTF8.GetBytes(password), salt, 64000, HashAlgorithmName.SHA1))
            {
                byte[] masterKey = pbkdf2.GetBytes(64);
                Array.Copy(masterKey, 0, encryptionKey, 0, 32);
                Array.Copy(masterKey, 32, hmacKey, 0, 20);
            }


            using FileStream fsInput = new(inputFilePath, FileMode.Open, FileAccess.Read);
            using FileStream fsOutput = new(outputFilePath, FileMode.Create, FileAccess.Write);
            fsInput.Seek(16 + 16, SeekOrigin.Begin);  // Skip the first 32 bytes (Salt and header)

            byte[] encryptedPage = new byte[1024 + 20 + 16];  // Page size + HMAC + IV
            byte[] decryptedPage;

            int pageNum = 1;
            while (fsInput.Read(encryptedPage, 0, encryptedPage.Length) > 0)
            {
                decryptedPage = CryptoHelper.DecryptPage(encryptedPage, encryptionKey, hmacKey, pageNum);
                fsOutput.Write(decryptedPage, 0, decryptedPage.Length);
                pageNum++;
            }
        }

        static async Task Main(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: SQLCipherDecryptor <input_file_path> <output_file_path> <password>");
                    return;
                }

                string inputFilePath = args[0];
                string outputFilePath = args[1];
                string password = args[2];

                await Decrypt(inputFilePath, outputFilePath, password);

                Console.WriteLine("Decryption completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.ToString()}");
            }
        }
    }
}
