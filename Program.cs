using CommandLine;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CertTest
{
    class Program
    {
        static int Main(string[] args)
        {
            var res = Parser.Default.ParseArguments<ListOptions, SearchOptions>(args).MapResult<ListOptions, SearchOptions, int>(List, Search, errs => 1);
            return res;
        }

        static int List(ListOptions opt)
        {
            using (var store = new X509Store(opt.StoreName, opt.StoreLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                PrintCert(store.Certificates);
            }
            return 0;
        }

        static int Search(SearchOptions opt)
        {
            using (var store = new X509Store(opt.StoreName, opt.StoreLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                var items = store.Certificates.Find(X509FindType.FindBySubjectName, opt.Subject, opt.ValidOnly.GetValueOrDefault(true));
                if (items != null && items.Count > 0)
                {
                    PrintCert(items);
                }
                else
                {
                    Console.WriteLine("No certificates found!");
                }
            }
            return 0;
        }

        static void PrintCert(X509Certificate2Collection certs)
        {
            var table = new Table();
            table.AddColumn("Friendly name");
            table.AddColumn("Subject");
            table.AddColumn("Thumbrint");
            table.AddColumn("Expires");
            table.AddColumn("Valid");
            foreach (var cert in certs)
                table.AddRow(cert.FriendlyName, cert.Subject, cert.Thumbprint, cert.NotAfter.ToString(), cert.Verify().ToString());
            AnsiConsole.Write(table);
        }

    }


    public class BaseOptions
    {

        [Option(Default = StoreLocation.LocalMachine, HelpText = "Specifies which certificate store to use. See https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storelocation for more information.")]
        public StoreLocation StoreLocation { get; set; } = StoreLocation.LocalMachine;

        [Option(Default = StoreName.My, HelpText = "Specifies store path to use. See https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename for more information.")]
        public StoreName StoreName { get; set; } = StoreName.My;
    }

    [Verb("list", HelpText = "Lists certificates in the store.")]
    public class ListOptions : BaseOptions
    {
    }

    [Verb("search", HelpText = "Search for a specific certificate by subject name.")]
    public class SearchOptions : BaseOptions
    {

        [Option(Required = true, HelpText = "Subject by which the certificate should be searched. This uses FindBySubjectName (see https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509findtype for more information)")]
        public string Subject { get; set; }

        [Option(Default = true, HelpText = "Search only valid certificates (default)")]
        public bool? ValidOnly { get; set; } = true;

    }

    public enum Command
    {
        List,
        Search
    }
}
