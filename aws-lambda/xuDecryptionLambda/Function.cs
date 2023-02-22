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

namespace xuDecryptionLambda;

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
    private readonly int partSize = 8 * (int)Math.Pow(2, 20); // 8 MB
    private readonly int writeThreshold = 6 * (int)Math.Pow(2, 20); // 5 MB

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
            this.targetFileName = this.sourceFileName = input.Records[0].S3.Object.Key;

            LambdaLogger.Log("Loading and checking source/destination buckets, file name...");
            this.sourceBucketName = Environment.GetEnvironmentVariable("sourcebucket");
            this.targetBucketName = Environment.GetEnvironmentVariable("targetbucket");
            this.keyId = Environment.GetEnvironmentVariable("privatekeyid");

            // validate information
            ValidateEnvironment();

            LambdaLogger.Log(Environment.GetEnvironmentVariable("AWS_REGION"));
            LambdaLogger.Log("Loading ciphertext...");
            GetObjectRequest readRequest = new()
            {
                BucketName = this.sourceBucketName,
                Key = this.sourceFileName,
            };

            this.client = new AmazonS3Client(RegionEndpoint.USEast1);
            using GetObjectResponse response = await this.client.GetObjectAsync(readRequest);
            if (response.HttpStatusCode != HttpStatusCode.OK)
            {
                throw new FileNotFoundException("Could not retrieve file from source bucket.");
            }

            LambdaLogger.Log("Loading metadata...");
            using CsvProcessor csvProcessor = new(await GetMetaDataAsync());

            // decrypt aes session key
            byte[] sessionKey = await DecryptSessionKey(csvProcessor.EncryptedSessionKey);

            LambdaLogger.Log(
                $"Preparing multipart upload with a minimal part size of {this.writeThreshold.ToString()} bytes");
            this.outputStream = new MemoryStream(this.partSize);
            await InitPartUploadAsync();

            LambdaLogger.Log("Decrypting...");
            using (this.aesGcm = new AesGcm(sessionKey))
            {
                await csvProcessor.ProcessDataAsync(DecryptCell, response.ResponseStream.ReadAsync, WritePartAsync,
                    CancellationToken.None);
            }

            LambdaLogger.Log("Completing multipart upload...");
            if (this.outputStream.Length > 0)
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
                AbortMultipartUploadRequest abortRequest = new()
                {
                    BucketName = this.targetBucketName,
                    Key = this.targetFileName,
                    UploadId = this.uploadId
                };
                await this.client.AbortMultipartUploadAsync(abortRequest);
            }

            return false;
        }
        finally
        {
            // cleanup some resources
            ArrayPool<byte>.Shared.Return(ivArray);
            this.client?.Dispose();
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
        using AmazonKeyManagementServiceClient kmsClient = new();
        DecryptRequest aesKeyDecryptionRequest = new()
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
            this.aesGcm.Decrypt(iv, cipherText, tag, plainText.AsSpan());

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
        InitiateMultipartUploadRequest initRequest = new()
        {
            BucketName = this.targetBucketName,
            StorageClass = S3StorageClass.Standard,
            Key = this.targetFileName,
        };

        // Initiate the upload.
        InitiateMultipartUploadResponse initResponse = await this.client.InitiateMultipartUploadAsync(initRequest);
        this.uploadId = initResponse.UploadId;
        this.tags = new List<PartETag>();
    }

    private async ValueTask WritePartAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await this.outputStream.WriteAsync(data, cancellationToken);
        if (this.outputStream.Length > this.writeThreshold)
        {
            await WritePartInternalAsync();
        }
    }

    private async Task WritePartInternalAsync()
    {
        LambdaLogger.Log($"Uploading part to position {this.filePosition}");
        this.outputStream.Position = 0;
        UploadPartRequest writePartRequest = new()
        {
            BucketName = this.targetBucketName,
            Key = this.targetFileName,
            UploadId = this.uploadId,
            PartNumber = this.partNumber,
            PartSize = this.outputStream.Length,
            FilePosition = this.filePosition,
            InputStream = this.outputStream,
        };

        // Upload a part and add the response to our list.
        UploadPartResponse resp = await this.client.UploadPartAsync(writePartRequest);
        this.tags.Add(new PartETag(this.partNumber, resp.ETag));
        this.filePosition += this.outputStream.Length;
        LambdaLogger.Log($"Completed upload of part #{this.partNumber} at file position {this.filePosition}.");
        this.partNumber++;
        // reset stream to be ready for next write
        this.outputStream.SetLength(0);
    }

    private async Task CompleteMultipartUploadAsync()
    {
        // Setup to complete the upload.
        CompleteMultipartUploadRequest completeRequest = new()
        {
            BucketName = this.targetBucketName,
            Key = this.targetFileName,
            UploadId = this.uploadId,
            PartETags = this.tags,
        };

        // Complete the upload.
        CompleteMultipartUploadResponse completeUploadResponse =
            await this.client.CompleteMultipartUploadAsync(completeRequest);
        LambdaLogger.Log(completeUploadResponse.HttpStatusCode == HttpStatusCode.OK
            ? "Multipart upload finished successfully."
            : $"Error when wrapping up multipart upload: {System.Text.Json.JsonSerializer.Serialize(completeUploadResponse)}");
    }

    #endregion

    #region Key and metadata file acquisition

    private async Task<string> GetMetaDataAsync()
    {
        GetObjectRequest readRequest = new()
        {
            BucketName = this.sourceBucketName,
            Key = $"{Path.GetFileNameWithoutExtension(this.sourceFileName)}_metadata.json"
        };

        using GetObjectResponse response = await this.client.GetObjectAsync(readRequest).ConfigureAwait(false);
        LambdaLogger.Log($"Response: {response.HttpStatusCode}");

        if (response.HttpStatusCode != HttpStatusCode.OK)
        {
            throw new Exception("Could not retrieve file from source bucket.");
        }

        using StreamReader sr = new(response.ResponseStream);
        return await sr.ReadToEndAsync();
    }

    #endregion
}