// See https://aka.ms/new-console-template for more information
using Certes;
using Certes.Acme;
using Microsoft.Extensions.Configuration;
using System.IO;
using System.Security.Cryptography;

var builder = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile($"config.json", true, true);

IConfiguration config = builder.Build();

bool isStage = Convert.ToBoolean(config.GetSection("isStageMode").Value);
string domain = config.GetSection("domain").Value;
string email = config.GetSection("email").Value;
string pfxPass = config.GetSection("pfxPassword").Value;
Uri wellKnownServer = isStage ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;

string currentDir = $"{Directory.GetCurrentDirectory()}";
string certPath = $"{currentDir}\\certs";
string keyFile = $"{certPath}\\{domain}.key";
string crtFile = $"{certPath}\\{domain}.crt";
string pfxFile = $"{certPath}\\{domain}.pfx";
string pemAccountPath = $"{currentDir}\\account{(isStage ? "-stage" : "")}.pem";


AcmeContext acme;

Console.WriteLine("Hello Certificate by LetsEncrypt");

Console.WriteLine($@"your config is:
is stage: {isStage}
domain: {domain}
email: {email}
pfx password: {pfxPass}
");

Console.WriteLine("if config is valid press y");
var command = Console.ReadKey().KeyChar;
if (command != 'y')
    Environment.Exit(0);

Console.WriteLine();
Console.WriteLine();
Console.WriteLine("plz w8...");
Console.WriteLine();
Console.WriteLine();

var pemKey = ReadFile(pemAccountPath);
if (string.IsNullOrWhiteSpace(pemKey))
{
    acme = new AcmeContext(wellKnownServer);
    await acme.NewAccount(email, true);

    //// Save the account key for later use
    pemKey = acme.AccountKey.ToPem();
    WriteLine(pemAccountPath, pemKey);
}


//var pemKey = "-----BEGIN EC PRIVATE KEY-----\r\nMHcCAQEEIHrxxWM2MkGh8WSXyE6IelUeEhnJJ7uQP13G1bkUyYl6oAoGCCqGSM49\r\nAwEHoUQDQgAEwlac87u8CM9HkIIaDv7+YG5+mSNdrP+v3W93For7bs+JRBkx0G37\r\ntTB8rhE/oTZSxDnEluMBZFfVPnwJZRSFQQ==\r\n-----END EC PRIVATE KEY-----\r\n";
//var pemKey = "-----BEGIN EC PRIVATE KEY-----\r\nMHcCAQEEIH14cTL5+XdrtP5kNCeDGP9TiEUpFAaX4XTQM3i2V4p/oAoGCCqGSM49\r\nAwEHoUQDQgAE+R+jRgF7zM2t1dQM7aEDFmwt8IJWvxplaaiHzJCBcIfIsRjoo2F6\r\ni9DXNxUu42Cppr9gNB8tyjQPd5cml61yzw==\r\n-----END EC PRIVATE KEY-----\r\n";
// Load the saved account key

var accountKey = KeyFactory.FromPem(pemKey);
//var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, accountKey);
acme = new AcmeContext(wellKnownServer, accountKey);
var account = await acme.Account();

var order = await acme.NewOrder(new[] { domain });

var authz = (await order.Authorizations()).First();
var dnsChallenge = await authz.Dns();
var dnsTxt = acme.AccountKey.DnsTxt(dnsChallenge.Token);
Console.WriteLine($"are you sure to set txt dns _acme-challenge.{domain} to {dnsTxt}");
Console.WriteLine();
Console.WriteLine("if ok? press any key");
Console.ReadKey();
Console.WriteLine();
Console.WriteLine();



var validate = await dnsChallenge.Validate();
Console.WriteLine($"validate txt dns _acme-challenge.{domain} is {validate.Status}");

if (validate.Status == Certes.Acme.Resource.ChallengeStatus.Valid)
{
    var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
    var cert = await order.Generate(new CsrInfo
    {
        CountryName = "CA",
        State = "Ontario",
        Locality = "Toronto",
        Organization = "Certes",
        OrganizationUnit = "Dev",
        CommonName = domain,
    }, privateKey);
    Console.WriteLine("certificate generated");


    if (!Directory.Exists(certPath))
        Directory.CreateDirectory(certPath);
    else
    {
        Directory.Delete(certPath, true);
        Directory.CreateDirectory(certPath);
    }

    if (!isStage)
    {
        var certPem = cert.ToPem();

        var pfxBuilder = cert.ToPfx(privateKey);
        var pfx = pfxBuilder.Build(domain, pfxPass);

        using (var sw = new StreamWriter(keyFile, false))
            sw.WriteLine(pemKey);
        Console.WriteLine($"pem file generated in path: {keyFile}");

        using (var sw = new StreamWriter(crtFile, false))
            sw.WriteLine(cert.Certificate);
        Console.WriteLine($"crt file generated in path: {crtFile}");

        File.WriteAllBytes(pfxFile, pfx);
        Console.WriteLine($"pfx file generated in path: {pfxFile}");
    }
    else
        Console.WriteLine("stage mode not generate files");
}
else
    Console.WriteLine($"retry again after some seconds...");

Console.WriteLine("finished");

Console.ReadKey();


static string ReadFile(string path)
{
    if (File.Exists(path))
        return File.ReadAllText(path);
    return "";
}

static void WriteLine(string path, string content)
{
    File.WriteAllText(path, content);
}