using System;
using System.IO;
using System.Security.Cryptography;

namespace PemConverter
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Missing Argument. Use PemLoader.exe yourPubKey.pem");
            }

            string pemFileName = args[0];
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(pemFileName));
            File.WriteAllText(
                $"{pemFileName.Split('.')[0]}.xml",
                rsa.ToXmlString(false));
        }
    }
}
