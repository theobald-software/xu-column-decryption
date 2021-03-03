# General Information
This template was created with the following command:
```
func init xuDecryptionFunction
```
with the dotnet option as runtime. It requires the [azure-functions-core-tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=windows%2Ccsharp%2Cbash#core-tools-versions) to be available. More information in the [Build and Deployment](#build-and-deployment) section.

It is meant to be a starting point for your own azure function for decrypting the XU generated encrypted data. The azure part of this project is basically the vanilla template and thus might not be configured correctly to match your security or other guidelines. Please **review the host.json and local.settings.json files before deployment to avoid putting your or your organization's data at risk**.

## Build and Deployment

Using Azure functions has the following requirements:
* An Azure account with an active subscription and a resource group
* An installation of the [.NET Core SDK 3.1](https://dotnet.microsoft.com/download/dotnet-core/3.1)
* The [Azure Functions Core Tools](https://www.npmjs.com/package/azure-functions-core-tools)

[-Source](https://docs.microsoft.com/en-us/azure/azure-functions/create-first-function-cli-csharp?tabs=azure-cli%2Cbrowser#configure-your-local-environment)

We used the windows installers of each of the tools

Before integrating the Function app into the Azure environment, you have to specify the names of the target and source container in your Azure Storage account. To do so open the `local.settings.json` and modify the values for the respective keys. If you do not use a connection string, please also delete the check for it in the functions code at `line 72`.
For us the deployment of the environment variables did not work reliably. It may be necessary to manually add the key-value pairs in the function app in the configuration.
The app assumes that the private key file is located in the target container. If your infrastructure is different, please adjust the code according to your needs.
You also have to specify the source container in the string of the BlobTrigger on `line 45`. Replace \<yourStorageBlob> with the path of the container which is targeted by the XU upload.

## Creating an Azure Function slot.
If you do **not** already have a slot for your Azure Function, create one by using the command:
```
az functionapp create --resource-group <your resource group> --consumption-plan-location <your location, e.g. westeurope> --runtime dotnet --functions-version 3 --name <your function name> --storage-account <your storage account>
```
where \<your function name> is the name of the functions slot in Azure. This name will be important for the deployment command in the next step.

## Deploying your app
Deploy your compiled function to the function slot in azure by invoking:
```
cd path/to/your/functions/source
```
to go to the source directory of your function.
```
func azure functionapp publish <your function name>
```
to build, publish and deploy the published app to the function slot.

## View the logs
To view the near real-time log stream use:
```
func azure functionapp logstream <your function name>
```

# Dependencies
The template depends on three NuGet packages. The `Microsoft.NET.Sdk.Functions` is linked in the template by default.

The `Microsoft.Azure.WebJobs.Extensions.Storage` package is used because the sample implementation does rely on a BlobTrigger. So whenever a file is uploaded to the blob, this function starts.

The third dependency is the `WindowsAzure.Storage` package. It is used when writing the results to another Azure blob storage. It is also required for loading the private key from a private blob as you might not want to store the private key in a simple Blob.
