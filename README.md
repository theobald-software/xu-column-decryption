# xu-coloumn-decryption
A collection of minimalistic sample apps to decrypt data which was extracted via Xtract Universal using the column encryption feature. Xtract Universal currently only supports the CSV Fileformat.
Note, that the default delimiter is ';' to match the Xtract Universal cloud destinations. The file CSV destination has ',' set as default. Set the delimiter in your file CSV destination to ';' to avoid confusion.

The following terminology is used in the readme files of the sample apps:
* target(Container/Bucket) for the place where the decrypted data will be written to. The apps (except AWS lambda) assume that the private key is located there, too.
* source(Container/Bucket) for the place where the encrypted data will arrive. This is the destination of the Xtract Universal extraction.

## Contents of this repository
### AWS Lambda Function
This sample shows how to decrypt data which was extracted to a S3 destination. It demonstrates how the decryption API provided by Theobald Software can be connected to a multipart upload to a S3 bucket.
### Azure Functions App
This sample shows how to decrypt data which was extracted to an Azure Storage destination.
### Local File App
This sample shows how to decrypt data which was extracted to a CSV Flat File destination.

**Every project contains a Readme.md file with further instructions regarding the projects requirements for building and deployment.**
# Technical Information
The sample apps use .NET6.0 as their runtime and are therefore platform independent. They are **not** configured to create self-contained binaries. Running them requires the .NET runtime (at least version 6.0) to be installed.
You can download the [.NET6.0 SDK here](https://dotnet.microsoft.com/download/dotnet).
Dependencies for the encryption are the Theobald.Decryption.Common library (.NET6.0) and the Theobald.Common library (NETStandard2.0). They only build on the respective dotnet frameworks and do not include any third-party libraries.
The two libraries are located in the "Theobald Software" directory and are referenced by the projects by default.

The interface for the decrypting applications is specifically designed to leave the user in control over all sensitive cryptographic data. That means that the code which actually decrypts the data is open source and part of the users application. However, keep in mind that changing the logic of this very code might result in the decryption process to fail.
The user-provided RSA private key is not used by Theobald Software owned code, but instead entirely under the users control.

This design decision implicates that of the cryptographic operations have to be handled by the user. The templates provide sample implementations of how to do these operations and thus use the interface provided by Theobald Software GmbH.

The templates are intended to be minimalistic and thus may not correctly reflect the integration into your cloud environment. The same applies for their security configuration.

However, the code regarding the interface usage and general decryption work should be well documented and understandable.

# Improvements
If you find any mistakes, missing information or see room for improvements, feel free to contact us or open an issue. We will try to respond as fast as possible.
Please keep in mind that the templates are supposed to be and stay simple. We will therefore reserve the right to decline bigger feature requests and the like.
