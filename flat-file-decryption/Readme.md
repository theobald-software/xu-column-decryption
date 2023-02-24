# General
This is a plain (meaning no integration into third party services) .NET console application implementing the decryption of data which was encrypted via Xtract Universal using the Column Encryption feature.
It opens FileStreams to to the specified files or the default locations and decrypts the ciphertext CSV file, writing the results to the target CSV file.

This template was created with the following command:
```
dotnet new console -n FileDecryption
```

Running the application requires the .NET6.0 and higher SDK. You can download the software [here](https://dotnet.microsoft.com/download/dotnet/6.0)

# Build and Deployment
You can build the code running
```
dotnet build -c Debug
```
or
```
dotnet build -c Release
```
from the command line in the root directory of the project (where the .csproj file is located).
To directly run it use `run` instead of `build` and append the command line arguments like so:
```
dotnet run -c Release -- --help
```
The `--` separates the arguments for the `dotnet` command and the arguments passed to the application.

Deploy the application by copying the files of the output directory `/bin/\[Release|Debug]/net6.0/` to the target directory of your extraction for example.
The `.exe` binary will only work on Windows. If your are on another operating system, use the `.dll` instead and run it like so:
```
dotnet FileDecryption.dll --help
```

Visit the [.NETCore documentation](https://docs.microsoft.com/en-us/dotnet/core/deploying/) for more information about deployment options, such as self-contained or single file deployment.