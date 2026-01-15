using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using System.Domain.Interfaces;
using System.Domain.Models;
using System.Domain.Services;
using System.Infrastructure.Services;
using System.Infrastructure.Repositories;
using System.Infrastructure.Data;

IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .Build();

var serviceProvider = new ServiceCollection()
    .AddSingleton<IConfiguration>(config)
    .AddSingleton<IScanner, GrypeRunner>()
    .AddSingleton<ISecurityRepository, SqliteRepository>()
    .AddSingleton<IVulnerabilityPersistenceService, VulnerabilityPersistenceService>()
    .AddSingleton<IRiskEvaluator, RiskEvaluator>()
    .AddSingleton<ReportGenerator>()
    .BuildServiceProvider();

Console.WriteLine(">>> CRA DEPENDENCY SENTINEL v1.1 (Integrity Enabled) <<<");

var evaluator = serviceProvider.GetRequiredService<IRiskEvaluator>();
var reporter = serviceProvider.GetRequiredService<ReportGenerator>();
var persistence = serviceProvider.GetRequiredService<IVulnerabilityPersistenceService>();

bool simulationMode = true; 
List<Vulnerability> vulnerabilities;

if (simulationMode)
{
    vulnerabilities = new List<Vulnerability>
    {
        new Vulnerability
        {
            Id = "CVE-2026-TEST",
            Package = "Microsoft.AspNetCore.Server.Kestrel",
            Severity = "High",
            Hash = "SHA256-TAMPERED-HASH-666", 
            FixAvailable = true,
            FirstDiscovered = DateTime.Now.AddDays(-5),
            ComponentZone = TrustZone.InternetFacing 
        }
    };
}
else
{
    var scanner = serviceProvider.GetRequiredService<IScanner>();
    vulnerabilities = scanner.Scan(Directory.GetCurrentDirectory()).Vulnerabilities.ToList();
}

// W40: Integrity Gatekeeper
bool integrityPassed = true;
foreach (var v in vulnerabilities)
{
    if (!persistence.CheckIntegrity(v.Package, v.Hash))
    {
        integrityPassed = false;
    }
}

if (!integrityPassed)
{
    Console.WriteLine("\n[HALT] Critical Error: Supply Chain Tampering Detected.");
    return 1;
}

// Process and Report
persistence.EnrichVulnerabilitiesWithHistory(vulnerabilities);
bool isCompliant = evaluator.IsCraCompliant(vulnerabilities);
reporter.Generate(vulnerabilities, isCompliant);

return isCompliant ? 0 : 1;