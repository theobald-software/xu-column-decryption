# PEM to XML key converter
This small application provides conversion of a normal pem formatted key as received from the AWS Key Management Service into the XML format, which is required by XtractUniversal.

It runs on NET 5.0.

The precompiled binaries are self-contained and should not require the installation of the NET 5.0 runtime.
The binaries were created with this command:
```
dotnet publish -r linux-x64 -c Release -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=true --self-contained
```
and

```
dotnet publish -r win-x64 -c Release -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=true --self-contained
```
