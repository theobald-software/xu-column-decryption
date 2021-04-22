using System;
using System.Buffers;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Theobald.Decryption.Common;
using Theobald.Decryption.Common.Csv;

namespace xuDecryptionFunction
{
    /// <summary>
    /// Sample Azure Functions app to demonstrate the decryption of data encrypted by Xtract Universal.
    /// </summary>
    public static class AzureStorageDecryption
    {
        private static AesGcm aesGcm;
        private static byte[] ivArray;

        #region Azure Storage Interop

        private static string sourceContainerName;
        private static string targetContainerName;
        private static string privateKeyFileName;
        private static string metadataFileName;
        private static CloudBlobContainer sourceContainer;
        private static CloudBlobContainer targetContainer;
        #endregion

        /// <summary>
        /// You can modify this code as you wish.
        ///
        /// Make sure not to change the decryption api interface logic to ensure the successful decryption of your data.
        /// </summary>
        /// <param name="encryptedFile"></param>
        /// <param name="name"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName("XUColumnDecryption")]
        public static async Task Run(
            [BlobTrigger("<yourStorageBlob>/{name}", Connection = "AzureWebJobsStorage")]
            Stream encryptedFile,
            string name,
            ILogger log)
        {
            // Saving the start time for diagnostics
            DateTime startTime = DateTime.Now;
            try
            {
                // The function triggers for every uploaded file.
                // We just exclude the metadata file, to have maximum flexibility.
                // Please adjust the trigger or filter for files to ignore to have the function match your purpose.
                if (name.Contains(".json") || name.Contains("metadata"))
                {
                    log.LogInformation("Metadata file upload. Exiting function.");
                    return;
                }

                ivArray = ArrayPool<byte>.Shared.Rent(12);
                // preparing decryption
                log.LogInformation("Loading account and container info...");
                string conString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
                sourceContainerName = Environment.GetEnvironmentVariable("SourceContainer");
                targetContainerName = Environment.GetEnvironmentVariable("TargetContainer");
                privateKeyFileName = Environment.GetEnvironmentVariable("PrivateKeyFileName");
                metadataFileName = $"{Path.GetFileNameWithoutExtension(name)}_metadata.json";

                // Remove this check if you are not using a connection string
                if (string.IsNullOrWhiteSpace(conString))
                {
                    throw new InvalidOperationException("No connection string was specified.");
                }

                if (string.IsNullOrWhiteSpace(privateKeyFileName))
                {
                    throw new InvalidOperationException("No private key file was specified.");
                }

                if (string.IsNullOrWhiteSpace(sourceContainerName))
                {
                    throw new InvalidOperationException("No source container was specified.");
                }

                if (string.IsNullOrWhiteSpace(targetContainerName))
                {
                    throw new InvalidOperationException("No target container was specified.");
                }

                CloudStorageAccount storageAccount = CloudStorageAccount.Parse(conString);
                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
                sourceContainer = blobClient.GetContainerReference(sourceContainerName);
                targetContainer = blobClient.GetContainerReference(targetContainerName);

                log.LogInformation($"C# Blob trigger function Processed blob\n Name: {name}\n Size: {encryptedFile.Length} Bytes");
                if (encryptedFile.Length == 0)
                {
                    for (int retriesRemaining = 3; retriesRemaining > 0; retriesRemaining--)
                    {
                        if (encryptedFile.Length > 0)
                        {
                            break;
                        }
                        else
                        {
                            log.LogInformation("No data on the stream yet. Retrying in two seconds.");
                            await Task.Delay(2000);
                        }
                    }

                    if (encryptedFile.Length == 0)
                    {
                        log.LogInformation("No data received.");
                        return;
                    }
                }

                log.LogInformation("Loading metadata...");
                log.LogInformation($"Expected metadata file name: {metadataFileName}");
                using CsvProcessor csvProcessor = new CsvProcessor(await GetMetaDataAsync());

                log.LogInformation("Decrypting session key...");
                using RSACryptoServiceProvider privateKey = new RSACryptoServiceProvider();
                privateKey.FromXmlString(await GetPrivateKeyAsync());
                // decryption AES session key
                byte[] sessionKey = privateKey.Decrypt(csvProcessor.EncryptedSessionKey, true);

                log.LogInformation("Opening target stream...");
                CloudBlockBlob plainTextBlob = targetContainer.GetBlockBlobReference(name);
                await using CloudBlobStream uploadStream = await plainTextBlob.OpenWriteAsync();

                // process and decrypt the data.
                log.LogInformation("Decrypting data...");
                using (aesGcm = new AesGcm(sessionKey))
                {
                    await csvProcessor.ProcessDataAsync(DecryptCell, encryptedFile.ReadAsync, uploadStream.WriteAsync,
                        CancellationToken.None);
                }

                log.LogInformation("Wrapping up upload to destination blob.");
                await uploadStream.CommitAsync();
            }
            catch (Exception e)
            {
                log.LogError(e.ToString());
            }
            finally
            {
                // cleanup some resources
                if (ivArray != null)
                {
                    ArrayPool<byte>.Shared.Return(ivArray);
                }

                log.LogInformation($"Function started at {startTime} terminated.");
            }
        }

        /// <summary>
        /// Splits the cell into the encoded iv, the ciphertext and the mac, created by the cipher.
        /// Afterwards this information is used to decrypt the data.
        ///
        /// The plaintext is returned to the caller.
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
                        BigInteger part = (byte)(current & 127);
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
        /// Loads the private key from the specified Blob.
        ///
        /// The string is then used to decrypt the session key.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="FileNotFoundException"></exception>
        private static async Task<string> GetPrivateKeyAsync()
        {
            CloudBlob blob = targetContainer.GetBlobReference(privateKeyFileName);
            if (!await blob.ExistsAsync())
            {
                throw new FileNotFoundException("No key file found. Aborting decryption");
            }

            using StreamReader sr = new StreamReader(await blob.OpenReadAsync());
            return await sr.ReadToEndAsync();
        }

        /// <summary>
        /// Loads the metadata file from the specified Blob.
        ///
        /// It contains information about the data set and the encrypted session key.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="FileNotFoundException"></exception>
        private static async Task<string> GetMetaDataAsync()
        {
            CloudBlob blob = sourceContainer.GetBlobReference(metadataFileName);
            if (!await blob.ExistsAsync())
            {
                throw new FileNotFoundException("No meta data file found. Aborting decryption");
            }

            using StreamReader sr = new StreamReader(await blob.OpenReadAsync());
            return await sr.ReadToEndAsync();
        }
    }
}
