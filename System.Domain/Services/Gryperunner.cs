using System.Domain.Interfaces;
using System.Domain.Models;

namespace System.Domain.Services;

public class GrypeRunner : IScanner
{
    public GrypeReport Scan(string path)
    {
        Console.WriteLine($"[LOG] Initiating supply-chain discovery at: {path}");
        
        return new GrypeReport
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new Vulnerability
                {
                    Id = "CVE-2024-001",
                    Severity = "Critical",
                    Package = "openssl",
                    FixAvailable = true
                },
                new Vulnerability
                {
                    Id = "CVE-2024-999",
                    Severity = "Low",
                    Package = "curl",
                    FixAvailable = false
                }
            }
        };
    }
}