using System.Domain.Interfaces;
using System.Domain.Models;

namespace System.Domain.Services;

public class RiskEvaluator : IRiskEvaluator
{
    public bool IsCraCompliant(List<Vulnerability> vulnerabilities)
    {
        var violations = vulnerabilities
            .Where(v => v.Severity == "Critical" && v.FixAvailable)
            .ToList();

        if (violations.Any())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[CRA VIOLATION] {violations.Count} critical vulnerabilities require immediate remediation.");
            Console.ResetColor();
            return false;
        }

        return true;
    }
}