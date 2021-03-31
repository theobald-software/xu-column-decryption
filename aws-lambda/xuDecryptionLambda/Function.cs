using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Lambda.Core;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using Theobald.Decryption.Common;
using Theobald.Decryption.Common.Csv;
using JsonSerializer = Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer;

[assembly: LambdaSerializer(typeof(JsonSerializer))]

namespace xuDecryptionLambda
{
    public class Function
    {
        private AesGcm aesGcm;
        private static byte[] ivArray;

        #region AWS S3 Interop

        private AmazonS3Client client;
        private MemoryStream outputStream;
        private string sourceBucketName = string.Empty;
        private string targetBucketName = string.Empty;
        private string targetFileName = string.Empty;
        private string sourceFileName = string.Empty;
        private string keyId = string.Empty;

        // multipart upload information
        private string uploadId;
        private List<PartETag> tags;
        private long filePosition;

        private int partNumber = 1;

        // partSize is essentially the buffer size of the memory stream, which caches the data for every single part
        private readonly int partSize = 8 * (int) Math.Pow(2, 20); // 8 MB
        private readonly int writeThreshold = 6 * (int) Math.Pow(2, 20); // 5 MB

        #endregion

        /// <summary>
        /// You can modify this code as you wish.
        ///
        /// Make sure not to change the decryption api interface logic to ensure the successful decryption of your data.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        public async Task<bool> FunctionHandler(S3EventNotification input, ILambdaContext context)
        {
            try
            {
                ivArray = ArrayPool<byte>.Shared.Rent(12);
                targetFileName = sourceFileName = input.Records[0].S3.Object.Key;

                LambdaLogger.Log("Loading and checking source/destination buckets, file name...");
                this.sourceBucketName = Environment.GetEnvironmentVariable("sourcebucket");
                this.targetBucketName = Environment.GetEnvironmentVariable("targetbucket");
                this.keyId = Environment.GetEnvironmentVariable("privatekeyid");

                // validate information
                ValidateEnvironment();

                LambdaLogger.Log(Environment.GetEnvironmentVariable("AWS_REGION"));
                LambdaLogger.Log("Loading ciphertext...");
                var readRequest = new GetObjectRequest
                {
                    BucketName = this.sourceBucketName,
                    Key = sourceFileName,
                };

                this.client = new AmazonS3Client(RegionEndpoint.USEast1);
                using GetObjectResponse response = await client.GetObjectAsync(readRequest);
                if (response.HttpStatusCode != HttpStatusCode.OK)
                {
                    throw new FileNotFoundException("Could not retrieve file from source bucket.");
                }

                LambdaLogger.Log("Loading metadata...");
                using CsvProcessor csvProcessor = new CsvProcessor(await GetMetaDataAsync());

                // decrypt aes session key
                byte[] sessionKey = await DecryptSessionKey(csvProcessor.EncryptedSessionKey);

                LambdaLogger.Log(
                    $"Preparing multipart upload with a minimal part size of {writeThreshold.ToString()} bytes");
                outputStream = new MemoryStream(partSize);
                await InitPartUploadAsync();

                LambdaLogger.Log("Decrypting...");
                using (aesGcm = new AesGcm(sessionKey))
                {
                    await csvProcessor.ProcessDataAsync(DecryptCell, response.ResponseStream.ReadAsync, WritePartAsync,
                        CancellationToken.None);
                }

                LambdaLogger.Log("Completing multipart upload...");
                if (outputStream.Length > 0)
                {
                    await WritePartInternalAsync();
                }

                await CompleteMultipartUploadAsync();
                return true;
            }
            catch (Exception ex)
            {
                LambdaLogger.Log($"Exception in PutS3Object: {ex}");
                if (!string.IsNullOrWhiteSpace(this.uploadId))
                {
                    // Abort the upload.
                    var abortRequest = new AbortMultipartUploadRequest
                    {
                        BucketName = targetBucketName,
                        Key = targetFileName,
                        UploadId = uploadId
                    };
                    await client.AbortMultipartUploadAsync(abortRequest);
                }

                return false;
            }
            finally
            {
                // cleanup some resources
                ArrayPool<byte>.Shared.Return(ivArray);
                client?.Dispose();
            }
        }

        private void ValidateEnvironment()
        {
            if (string.IsNullOrWhiteSpace(this.sourceBucketName))
            {
                throw new InvalidOperationException("No source bucket was specified.");
            }

            if (string.IsNullOrWhiteSpace(this.targetBucketName))
            {
                throw new InvalidOperationException("No target bucket was specified.");
            }

            if (string.IsNullOrWhiteSpace(this.targetFileName))
            {
                throw new InvalidOperationException("No target file was specified.");
            }

            if (string.IsNullOrWhiteSpace(this.sourceFileName))
            {
                throw new InvalidOperationException("No source file was specified.");
            }

            if (string.IsNullOrWhiteSpace(this.keyId))
            {
                throw new InvalidOperationException("No key id was specified.");
            }
        }

        private async Task<byte[]> DecryptSessionKey(byte[] encryptedSessionKey)
        {
            using var kmsClient = new AmazonKeyManagementServiceClient();
            DecryptRequest aesKeyDecryptionRequest = new DecryptRequest
            {
                EncryptionAlgorithm = EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1,
                CiphertextBlob = new MemoryStream(encryptedSessionKey),
                KeyId = this.keyId
            };
            DecryptResponse decryptionResponse = await kmsClient.DecryptAsync(aesKeyDecryptionRequest);
            return decryptionResponse.Plaintext.ToArray();
        }

        #region Crypto

        /// <summary>
        /// Splits the cell into the encoding iv, the ciphertext and the mac, created by the cipher.
        /// </summary>
        /// <param name="input">We have to use <see cref="Memory{T}"/> here since it is passed as a delegate</param>
        /// <returns>the plaintext as a byte array.</returns>
        /// <exception cref="DecryptionException">The input array is not correctly formatted.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified,
        /// or the decryption operation failed for some other reason.
        /// This might also occur if the iv does not match the one which was used for encryption.</exception>
        private byte[] DecryptCell(Memory<byte> input)
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

            var rawCell = input.Span;
            BigInteger ivBigInt = Read7BitBigInt(rawCell, out int encodedIvLength);

            var iv = ivArray.AsSpan(0, 12);
            if (ivBigInt.TryWriteBytes(iv, out _))
            {
                var cipherText = rawCell.Slice(encodedIvLength, rawCell.Length - 16 - encodedIvLength);
                var tag = rawCell.Slice(rawCell.Length - 16, 16);
                byte[] plainText = new byte[rawCell.Length - encodedIvLength - 16];
                aesGcm.Decrypt(iv, cipherText, tag, plainText.AsSpan());

                // clean iv array
                Array.Fill<byte>(ivArray, 0);
                return plainText;
            }

            throw new DecryptionException("Could not extract the iv from the raw cell data.");
        }

        #endregion

        #region Multipart Upload

        private async Task InitPartUploadAsync()
        {
            var initRequest = new InitiateMultipartUploadRequest()
            {
                BucketName = targetBucketName,
                StorageClass = S3StorageClass.Standard,
                Key = targetFileName,
            };

            // Initiate the upload.
            InitiateMultipartUploadResponse initResponse = await client.InitiateMultipartUploadAsync(initRequest);
            uploadId = initResponse.UploadId;
            tags = new List<PartETag>();
        }

        private async ValueTask WritePartAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        {
            await outputStream.WriteAsync(data, cancellationToken);
            if (outputStream.Length > writeThreshold)
            {
                await WritePartInternalAsync();
            }
        }

        private async Task WritePartInternalAsync()
        {
            LambdaLogger.Log($"Uploading part to position {filePosition}");
            outputStream.Position = 0;
            var writePartRequest = new UploadPartRequest
            {
                BucketName = targetBucketName,
                Key = targetFileName,
                UploadId = uploadId,
                PartNumber = partNumber,
                PartSize = outputStream.Length,
                FilePosition = filePosition,
                InputStream = outputStream,
            };

            // Upload a part and add the response to our list.
            var resp = await client.UploadPartAsync(writePartRequest);
            tags.Add(new PartETag(partNumber, resp.ETag));
            filePosition += outputStream.Length;
            LambdaLogger.Log($"Completed upload of part #{partNumber} at file position {filePosition}.");
            partNumber++;
            // reset stream to be ready for next write
            outputStream.SetLength(0);
        }

        private async Task CompleteMultipartUploadAsync()
        {
            // Setup to complete the upload.
            CompleteMultipartUploadRequest completeRequest = new CompleteMultipartUploadRequest
            {
                BucketName = targetBucketName,
                Key = targetFileName,
                UploadId = uploadId,
                PartETags = tags,
            };

            // Complete the upload.
            CompleteMultipartUploadResponse completeUploadResponse =
                await client.CompleteMultipartUploadAsync(completeRequest);
            LambdaLogger.Log(completeUploadResponse.HttpStatusCode == HttpStatusCode.OK
                ? "Multipart upload finished successfully."
                : $"Error when wrapping up multipart upload: {System.Text.Json.JsonSerializer.Serialize(completeUploadResponse)}");
        }

        #endregion

        #region Key and metadata file acquisition

        private async Task<string> GetMetaDataAsync()
        {
            var readRequest = new GetObjectRequest
            {
                BucketName = this.sourceBucketName,
                Key = "metadata.json"
            };

            using GetObjectResponse response = await client.GetObjectAsync(readRequest).ConfigureAwait(false);
            LambdaLogger.Log($"Response: {response.HttpStatusCode}");

            if (response.HttpStatusCode != HttpStatusCode.OK)
            {
                throw new Exception("Could not retrieve file from source bucket.");
            }

            using StreamReader sr = new StreamReader(response.ResponseStream);
            return await sr.ReadToEndAsync();
        }

        #endregion
    }
}