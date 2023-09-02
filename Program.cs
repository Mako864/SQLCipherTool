using System.Text;

namespace SQLCipherDecryptor
{
    class Program
    {
        public static async Task DecryptFile(string filenameIn, byte[] password, string filenameOut)
        {
            try
            {
                // Validate arguments
                if (filenameIn == null || !(filenameIn is string))
                {
                    throw new InvalidOperationException("filenameIn must be a string.");
                }
                if (password == null || !(password is byte[]))
                {
                    throw new InvalidOperationException("password must be a byte array.");
                }
                if (filenameOut == null || !(filenameOut is string))
                {
                    throw new InvalidOperationException("filenameOut must be a string.");
                }

                // Log the start of the decryption process and input parameters
                Console.WriteLine("Starting decryption.");
                Console.WriteLine($"Input File: {filenameIn}");
                Console.WriteLine($"Output File: {filenameOut}");

                // Read encrypted file
                byte[] raw;
                using (FileStream fs = new(filenameIn, FileMode.Open, FileAccess.Read))
                {
                    raw = new byte[fs.Length];
                    await fs.ReadAsync(raw, 0, (int)fs.Length);
                }

                // Decrypt
                byte[] dec = CryptoHelper.DecryptDefault(raw, password);

                Console.WriteLine("Decryption completed. Writing to output file.");

                // Write decrypted file
                using (FileStream fs = new(filenameOut, FileMode.Create, FileAccess.Write))
                {
                    await fs.WriteAsync(dec, 0, dec.Length);
                }

                // Log completion
                Console.WriteLine("Decryption and output file writing completed successfully.");
            }
            catch (Exception ex)
            {
                // Log any exceptions
                Console.WriteLine($"An error occurred: {ex}");
            }
        }

        static async Task Main(string[] args)
        {
            try
            {
                if (args.Length < 4)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("Encrypt: -e <input_file_path> <output_file_path> <password>");
                    Console.WriteLine("Decrypt: -d <input_file_path> <output_file_path> <password>");
                    return;
                }

                string flag = args[0];

                if (flag == "-d")
                {
                    string inputFilePath = args[1];
                    string outputFilePath = args[2];
                    string password = args[3];

                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                    await DecryptFile(inputFilePath, passwordBytes, outputFilePath);

                    Console.WriteLine("Decryption completed.");
                }
                else if (flag == "-e")
                {
                    string inputDbFilePath = args[1];
                    string outputDbFilePath = args[2];
                    string encryptionKey = args[3];

                    Encryptor.EncryptDatabase(inputDbFilePath, outputDbFilePath, encryptionKey);

                }
                else
                {
                    Console.WriteLine("Invalid flag. Use -e for encryption and -d for decryption.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex}");
            }
        }
    }
}



