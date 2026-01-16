using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using System.Domain.Interfaces;
using System.Domain.Models;
using System.Domain.Services;
using System.Infrastructure.Services;
using System.Infrastructure.Repositories;

// --- CONFIGURATION ---
IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .Build();

// --- DEPENDENCY INJECTION ---
var serviceProvider = new ServiceCollection()
    .AddSingleton<IConfiguration>(config)
    .AddSingleton<IScanner, GrypeRunner>()
    .AddSingleton<ISecurityRepository, SqliteRepository>()
    .AddSingleton<IVulnerabilityPersistenceService, VulnerabilityPersistenceService>()
    .AddSingleton<IRiskEvaluator, RiskEvaluator>()
    .AddSingleton<IdentityService>() // W41 Identity Logic
    .AddSingleton<ReportGenerator>()
    .BuildServiceProvider();

// --- STARTUP ---
Console.WriteLine(">>> CRA DEPENDENCY SENTINEL v1.2 (Full Security Suite) <<<");

var evaluator = serviceProvider.GetRequiredService<IRiskEvaluator>();
var reporter = serviceProvider.GetRequiredService<ReportGenerator>();
var persistence = serviceProvider.GetRequiredService<IVulnerabilityPersistenceService>();
var idService = serviceProvider.GetRequiredService<IdentityService>();

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
            Hash = "SHA256-ORIGINAL-HASH-999", 
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

// 1. W40: INTEGRITY CHECK (CRYPTOGRAPHIC GATEKEEPER)
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
    Console.WriteLine("\n[HALT] Critical Error: Supply Chain Tampering Detected. Aborting for safety.");
    return 1;
}

// 2. PERSISTENCE & HISTORY
persistence.EnrichVulnerabilitiesWithHistory(vulnerabilities);

// 3. W45: RISK EVALUATION
bool isCompliant = evaluator.IsCraCompliant(vulnerabilities);
AuditSignature? approval = null;

// 4. W41: IDENTITY OVERRIDE CHALLENGE
if (!isCompliant)
{
    Console.WriteLine("\n[W41 IDENTITY CHALLENGE] Compliance Failed.");
    Console.WriteLine("Enter OIDC Admin Token for Override (or press Enter to confirm failure):");
    string? token = Console.ReadLine();

    if (!string.IsNullOrEmpty(token) && idService.IsAuthorized(token, out var officer))
    {
        approval = new AuditSignature 
        { 
            OfficerName = officer!.Username, 
            Reason = "SLA Exception: Legacy component maintenance window",
            OAuthTokenThumbprint = "sha256:oidc:session:a1b2c3d4",
            SignedAt = DateTime.Now 
        };
        isCompliant = true; // Override result
        Console.WriteLine(">>> IDENTITY VERIFIED. COMPLIANCE EXCEPTION SIGNED. <<<");
    }
}

// 5. REPORTING
reporter.Generate(vulnerabilities, isCompliant, approval);

return isCompliant ? 0 : 1;