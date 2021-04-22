using System;
using System.Buffers;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Theobald.Decryption.Common;
using Theobald.Decryption.Common.Csv;

namespace FileDecryption
{
    internal static class Program
    {
        private static AesGcm aesGcm;
        private static byte[] ivArray;

        private static string targetFile = "plaintext.csv";
        private static string sourceFile = "ciphertext.csv";
        private static string metaDataFile;
        private static string keyFile = "private.xml";

        /// <summary>
        /// Decrypts a specified csv file, which was created by XtractUniversal with column encryption enabled.
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        private static async Task Main(string[] args)
        {
            if (!GetInfoFromArgs(args))
            {
                return;
            }

            // build metadata file name
            metaDataFile = metaDataFile ?? $"{Path.GetFileNameWithoutExtension(sourceFile)}_metadata.json";

            ivArray = ArrayPool<byte>.Shared.Rent(12);

            await using FileStream metaDataStream = File.Open(metaDataFile, FileMode.Open, FileAccess.Read);
            using StreamReader reader = new StreamReader(metaDataStream);

            using CsvProcessor csvProcessor = new CsvProcessor(await reader.ReadToEndAsync());

            string keyXml = await File.ReadAllTextAsync(keyFile);
            using RSACryptoServiceProvider privateKey = new RSACryptoServiceProvider();
            privateKey.FromXmlString(keyXml);
            byte[] sessionKey = privateKey.Decrypt(csvProcessor.EncryptedSessionKey, true);

            await using FileStream target = File.Open(targetFile, FileMode.Create, FileAccess.Write);
            await using FileStream fs = File.Open(sourceFile, FileMode.Open, FileAccess.Read);
            using (aesGcm = new AesGcm(sessionKey))
            {
                await csvProcessor.ProcessDataAsync(DecryptCell, fs.ReadAsync, target.WriteAsync,
                    CancellationToken.None);
                ArrayPool<byte>.Shared.Return(ivArray);
            }
        }

        /// <summary>
        /// Splits the cell into the encoding iv, the ciphertext and the mac, created by the cipher.
        /// </summary>
        /// <param name="input">We have to use <see cref="Memory{T}"/> here since it is passed as a delegate</param>
        /// <returns>the plaintext as a byte array.</returns>
        /// <exception cref="DecryptionException">The input array is not correctly formatted.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified,
        /// or the decryption operation failed for some other reason.
        /// This might also occur if the iv does not match the one which was used for encryption.</exception>
        private static byte[] DecryptCell(Memory<byte> input)
        {
            static BigInteger Read7BitBigInt(ReadOnlySpan<byte> span, out int bytesRead)
            {
                try
                {
                    BigInteger ret = BigInteger.Zero;
                    int current;
                    int position = 0;
                    do
                    {
                        current = span[position];
                        BigInteger part = (byte) (current & 127);
                        ret |= part << (7 * position);
                        position++;
                    } while ((current & 128) > 0);

                    bytesRead = position;
                    return ret;
                }
                catch (Exception e)
                {
                    throw new DecryptionException("Could not read iv from byte slice.", e);
                }
            }

            Span<byte> rawCell = input.Span;
            BigInteger ivBigInt = Read7BitBigInt(rawCell, out int encodedIvLength);

            Span<byte> iv = ivArray.AsSpan(0, 12);
            if (ivBigInt.TryWriteBytes(iv, out _))
            {
                Span<byte> cipherText = rawCell.Slice(encodedIvLength, rawCell.Length - 16 - encodedIvLength);
                Span<byte> tag = rawCell.Slice(rawCell.Length - 16, 16);
                byte[] plainText = new byte[rawCell.Length - encodedIvLength - 16];
                aesGcm.Decrypt(iv, cipherText, tag, plainText.AsSpan());

                // clean iv array
                Array.Fill<byte>(ivArray, 0);
                return plainText;
            }

            throw new DecryptionException("Could not extract the iv from the raw cell data.");
        }

        /// <summary>
        /// Checks the cli arguments for consistency and return them for usage.
        /// -m/ --metadata metadata file path
        /// -t/ --target target file path
        /// -s/ --source source file path
        /// -k/ --key key file path
        /// -h/ --help print help
        /// </summary>
        /// <param name="args"></param>
        private static bool GetInfoFromArgs(string[] args)
        {
            if (args[0] == "-h" || args[0] == "--help")
            {
                // help requested.
                Console.WriteLine(
                    "This application provides a sample implementation to decrypt data which was encrypted via Xtract Universals using the Column Encryption feature.");
                Console.WriteLine("Usage:");
                Console.WriteLine("fileDecryption.exe -h/--help for this help");
                Console.WriteLine("-t/ --target \t\tpath/to/plaintext.csv");
                Console.WriteLine("-s/ --source \t\tpath/to/ciphertext.csv");
                Console.WriteLine("-m/ --metadata \t\tpath/to/metadata.json");
                Console.WriteLine("-k/ --key \t\tpath/to/privateKey.xml");
                Console.WriteLine(
                    "The switches default to the listed file name in the current directory of the executable.");
                return false;
            }

            for (int i = 0; i < args.Length; i += 2)
            {
                switch (args[i])
                {
                    case "-t":
                    case "--target":
                        string tempPath = args[i + 1];
                        if (tempPath[0] == '-')
                        {
                            Console.WriteLine("Missing value for argument -t.");
                            return false;
                        }

                        // TODO: validate path
                        targetFile = tempPath;

                        break;
                    case "-s":
                    case "--source":
                        if (!CheckArg("-s", i, ref sourceFile, args))
                        {
                            return false;
                        }

                        break;
                    case "-m":
                    case "--metadata":
                        if (!CheckArg("-m", i, ref metaDataFile, args))
                        {
                            return false;
                        }

                        break;
                    case "-k":
                    case "--key":
                        if (!CheckArg("-k", i, ref keyFile, args))
                        {
                            return false;
                        }

                        break;
                }
            }

            return true;
        }

        private static bool CheckArg(string arg, int currentIndex, ref string targetVariable, string[] args)
        {
            string tempPath = args[currentIndex + 1];
            if (tempPath[0] == '-')
            {
                Console.WriteLine($"Missing value for argument {arg}.");
                return false;
            }

            if (File.Exists(tempPath))
            {
                targetVariable = tempPath;
                return true;
            }
            else
            {
                Console.WriteLine("File was not found at: " + tempPath);
                return false;
            }
        }
    }
}