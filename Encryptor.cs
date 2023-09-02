using SQLitePCL;
using System;
using System.IO;

namespace SQLCipherDecryptor
{
    public class Encryptor
    {
        public static void EncryptDatabase(string inputFilePath, string outputFilePath, string key)
        {
            Console.WriteLine($"Input File: {inputFilePath}");
            Console.WriteLine($"Output File: {outputFilePath}");

            Batteries_V2.Init();

            // Open the source database
            sqlite3 db;
            var rc = raw.sqlite3_open(inputFilePath, out db);

            if (rc == raw.SQLITE_OK)
            {
                rc = raw.sqlite3_exec(db, $"ATTACH DATABASE '{outputFilePath}' AS encrypted KEY '{key}';");
                Console.WriteLine($"Attaching {outputFilePath} as new encrypted DB...");

                if (rc != raw.SQLITE_OK)
                {
                    utf8z errMsgUtf8 = raw.sqlite3_errmsg(db);
                    string errMsg = errMsgUtf8.utf8_to_string();

                    Console.WriteLine($"Error attaching database. SQLite Error Message: {errMsg}");
                    return;
                }

                Console.WriteLine("Setting PRAGMAs and exporting tables...");
                // SQLCipher3 compatiblity.
                rc = raw.sqlite3_exec(db, "PRAGMA encrypted.cipher_page_size = 1024;");
                rc = raw.sqlite3_exec(db, "PRAGMA encrypted.kdf_iter = 64000;");
                rc = raw.sqlite3_exec(db, "PRAGMA encrypted.cipher_hmac_algorithm = HMAC_SHA1;");
                rc = raw.sqlite3_exec(db, "PRAGMA encrypted.cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;");

                rc = raw.sqlite3_exec(db, "SELECT sqlcipher_export('encrypted');");

                if (rc != raw.SQLITE_OK)
                {
                    utf8z errMsgUtf8 = raw.sqlite3_errmsg(db);
                    string errMsg = errMsgUtf8.utf8_to_string();

                    Console.WriteLine($"Error exporting to encrypted database. SQLite Error Message: {errMsg}");
                    return;
                }
                Console.WriteLine("Detaching encrypted DB...");
                rc = raw.sqlite3_exec(db, "DETACH DATABASE encrypted;");

                if (rc != raw.SQLITE_OK)
                {
                    utf8z errMsgUtf8 = raw.sqlite3_errmsg(db);
                    string errMsg = errMsgUtf8.utf8_to_string();
                    Console.WriteLine($"Error detaching encrypted database. SQLite Error Message: {errMsg}");
                    return;
                }

                raw.sqlite3_close(db);
            }
            else
            {
                Console.WriteLine("Couldn't open the database");
            }

            Console.WriteLine("Encryption completed.");
        }
    }
}
