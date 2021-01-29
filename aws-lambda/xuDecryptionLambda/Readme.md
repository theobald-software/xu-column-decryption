# General Information
This template was created with the following command:
```
dotnet new serverless.EmptyServerless -n xuDecryptionLambda
```

It is meant to be a starting point for your own lambda function for decrypting the XU generated encrypted data. The lambda part of this project is basically the vanilla template and thus might not be configured correctly to match your security or other guidelines. Please **review the serverless.template file before deployment to avoid putting your or your organizations data at risk**.

You may edit the template to customize the function or add more functions and other resources needed by your application.

# Build and Deployment

You can deploy your application using [.NETCore](https://dotnet.microsoft.com/download/dotnet-core/3.1) in combination with the [Amazon.Lambda.Tools Global Tool](https://github.com/aws/aws-extensions-for-dotnet-cli#aws-lambda-amazonlambdatools) from the command line.

Install Amazon.Lambda.Tools Global Tools if not already installed.
```
dotnet tool install -g Amazon.Lambda.Tools
```

If already installed check if new version is available.
```
dotnet tool update -g Amazon.Lambda.Tools
```

Deploy application
```
dotnet lambda deploy-function
```

# Setup

You have to set the triggers for your Lambda function yourself. We do not provide any presets for this area.
If you change the name of the files or the name of the handler, you also have to change the `serverless.template` file accordingly.
The names for the source and target buckets are retrieved from environment variables set for your Lambda function. You will have to set them yourself. If you do not provide these variables, the function code will throw an error, when checking for them.
The variables are named like so:
sourcebucket
targetbucket

The private key is assumed to be located in the target bucket. The assumed name is "private.xml".