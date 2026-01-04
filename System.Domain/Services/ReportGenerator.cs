using System.Domain.Models;

namespace System.Domain.Services;

public class ReportGenerator
{
    public void Generate(GrypeReport report, bool compliant)
    {
        Console.WriteLine("\n=== VulnerABILITY REPORT ===");

        foreach (var v in report.Vulnerabilities)
        {
            Console.WriteLine(
                $"- [{v.Severity}] {v.Id} | Package: {v.Package} | Fix Available: {v.FixAvailable}"
            );
        }

        Console.WriteLine("\n=== CRA COMPLIANCE RESULT ===");

        Console.ForegroundColor = compliant ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(compliant ? "PASS ✅" : "FAIL ❌");
        Console.ResetColor();
    }
}