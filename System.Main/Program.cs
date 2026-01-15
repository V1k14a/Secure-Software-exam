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

// 1. Configure Dependency Injection
var serviceProvider = new ServiceCollection()
    .AddSingleton<IConfiguration>(config)
    .AddSingleton<IScanner, GrypeRunner>() // Infra
    .AddSingleton<ISecurityRepository, SqliteRepository>() // Infra
    .AddSingleton<IVulnerabilityPersistenceService, VulnerabilityPersistenceService>() // Domain
    .AddSingleton<IRiskEvaluator, RiskEvaluator>() // Domain
    .AddSingleton<ReportGenerator>() // Domain
    .BuildServiceProvider();

// 2. Start Application
Console.WriteLine(">>> CRA DEPENDENCY SENTINEL v1.0 <<<");

var evaluator = serviceProvider.GetRequiredService<IRiskEvaluator>();
var reporter = serviceProvider.GetRequiredService<ReportGenerator>();

// SET TO TRUE TO TEST THREAT MODELING LOGIC
bool simulationMode = true; 
List<Vulnerability> vulnerabilities;

if (simulationMode)
{
    Console.WriteLine("[TEST] Running Threat-Modeling Simulation...");
    vulnerabilities = new List<Vulnerability>
    {
        new Vulnerability
        {
            Id = "CVE-2026-TEST",
            Package = "Microsoft.AspNetCore.Server.Kestrel",
            Severity = "High",
            FixAvailable = true,
            FirstDiscovered = DateTime.Now.AddDays(-5), // Older than 24h
            ComponentZone = TrustZone.InternetFacing    // HIGH RISK ZONE
        }
    };
}
else
{
    var scanner = serviceProvider.GetRequiredService<IScanner>();
    var report = scanner.Scan(Directory.GetCurrentDirectory());
    vulnerabilities = report.Vulnerabilities.ToList();
}

// 3. Process and Report
bool isCompliant = evaluator.IsCraCompliant(vulnerabilities);
reporter.Generate(vulnerabilities, isCompliant);

// Exit code = CRA decision
return isCompliant ? 0 : 1;