using System.Security.Cryptography;
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
                using (FileStream fs = new FileStream(filenameOut, FileMode.Create, FileAccess.Write))
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
                //if (args.Length < 3)
                //{
                //    Console.WriteLine("Usage: SQLCipherDecryptor <input_file_path> <output_file_path> <password>");
                //    return;
                //}

                //string inputFilePath = args[0];
                //string outputFilePath = args[1];
                //string password = args[2];

                string inputFilePath = "C:\\Users\\mikha\\Desktop\\ChromaCS\\bin\\Debug\\net6.0\\dbs\\dataenc_glb.db";
                string outputFilePath = "C:\\Users\\mikha\\Desktop\\ChromaCS\\bin\\Debug\\net6.0\\dbs\\glb.db";
                string password = "9bf9c6ed9d537c399a6c4513e92ab24717e1a488381e3338593abd923fc8a13b";

                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                await DecryptFile(inputFilePath, passwordBytes, outputFilePath);

                Console.WriteLine("Decryption completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.ToString()}");
            }
        }
    }
}
