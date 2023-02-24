# General Information
This template was created with the following command:
```
dotnet new serverless.EmptyServerless -n xuDecryptionLambda
```
The project template can be found [here](https://dotnetnew.azurewebsites.net/template/Amazon.Lambda.Templates/AWS.Lambda.Serverless.Empty.CSharp).

It is meant to be a starting point for your own lambda function for decrypting the XU generated encrypted data.
The lambda part of this project is basically the vanilla template and thus will most likely not be configured correctly to match your security or other guidelines.
Please **review the serverless.template file before deployment to avoid putting your or your organizations data at risk**.

Edit the template to customize the function or add more functions and other resources needed by your application.

Deployment might require additional setup steps on the users machine.

# Build and Deployment

You can deploy your application using [.NET6.0](https://dotnet.microsoft.com/download/dotnet) in combination with the [Amazon.Lambda.Tools Global Tool](https://github.com/aws/aws-extensions-for-dotnet-cli#aws-lambda-amazonlambdatools) from the command line.

Install Amazon.Lambda.Tools Global Tools if not already installed.
```
dotnet tool install -g Amazon.Lambda.Tools
```

If already installed check if new version is available.
```
dotnet tool update -g Amazon.Lambda.Tools
```

Deploy the application in interactive mode (runtime is netcoreapp3.1)
```
dotnet lambda deploy-function
```

or with a config file.
```
dotnet lambda deploy-function -cfg aws-lambda-tools-defaults.json
```
Note that the configuration file, which is provided with the repository is only a sample, which will not work with your environment.
Modify the file to fit your needs before deploying.
The profile files contents look like this:

```
[default]
aws_access_key_id = <access-key-id>
aws_secret_access_key = <secret-key>
```

# Setup

Xtract Universal uses the multipart api to upload the data. Hence the multipart trigger has to be configured in your lambda function.
If you change the name of the files or the name of the handler, you also have to change the `serverless.template` file accordingly.

The function code uses some environment variables, which can be set in the function's configuration tab. The function checks its environment including the variables and throws an error if one of the values can not be found.

```
sourcebucket
```
The source bucket is the name of the bucket, from which the function loads the metadata and ciphertext.

```
targetbucket
```
The target bucket is the name of the bucket, to which the function uploads the plaintext.

```
privatekeyid
```
The private key id is the identifier of the key pair in your KMS. Several formats are permitted:
* Key ID: 1234abcd-12ab-34cd-56ef-1234567890ab (we tested the function with this one)
* Key ARN: arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
* Alias name: alias/ExampleAlias
* Alias ARN: arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias

For more information regarding the KMS integration view the [API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).
