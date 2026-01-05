using System.Domain.Models;
using System.Text;

namespace System.Domain.Services;

public class ReportGenerator
{
    public void Generate(IEnumerable<Vulnerability> vulnerabilities, bool compliant)
    {
        Console.WriteLine("\n" + new string('=', 40));
        Console.WriteLine("        CRA SECURITY AUDIT REPORT");
        Console.WriteLine(new string('=', 40));

        if (!vulnerabilities.Any())
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  [OK] No vulnerabilities found.");
            Console.ResetColor();
        }
        else
        {
            foreach (var v in vulnerabilities)
            {
                if (v.Severity == "Critical" || v.AgeInDays > 2) Console.ForegroundColor = ConsoleColor.Yellow;
                
                string slaStatus = v.AgeInDays > 2 ? "!!! SLA EXPIRED !!!" : "Within SLA";
                
                Console.WriteLine($"- [{v.Severity.ToUpper()}] {v.Id}");
                Console.WriteLine($"  Package: {v.Package} | Fix: {v.FixAvailable}");
                Console.WriteLine($"  Age: {v.AgeInDays} days ({slaStatus})");
                Console.WriteLine(new string('-', 30));
                Console.ResetColor();
            }
        }

        Console.WriteLine("\n=== CRA COMPLIANCE RESULT ===");
        Console.ForegroundColor = compliant ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(compliant ? ">>> STATUS: PASS ✅" : ">>> STATUS: FAIL ❌");
        Console.ResetColor();
        Console.WriteLine(new string('=', 40));
        
        GenerateMarkdownReport(vulnerabilities, compliant);
    }

    private void GenerateMarkdownReport(IEnumerable<Vulnerability> vulns, bool compliant)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Cyber Resilience Act (CRA) Compliance Report");
        sb.AppendLine($"**Generated:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"**Final Verdict:** {(compliant ? "PASS" : "FAIL")}");
        sb.AppendLine("\n## Summary");
        sb.AppendLine($"- Total Components Scanned: (Calculated from SBOM)");
        sb.AppendLine($"- Total Vulnerabilities Found: {vulns.Count()}");
        
        sb.AppendLine("\n## Detailed Vulnerability List");
        sb.AppendLine("| ID | Severity | Package | Fix Available | Age (Days) |");
        sb.AppendLine("|----|----------|---------|---------------|------------|");
        
        foreach (var v in vulns)
        {
            sb.AppendLine($"| {v.Id} | {v.Severity} | {v.Package} | {v.FixAvailable} | {v.AgeInDays} |");
        }

        File.WriteAllText("CRA_Compliance_Report.md", sb.ToString());
        Console.WriteLine($"\n[AUDIT] Professional report saved to: {Path.GetFullPath("CRA_Compliance_Report.md")}");
    }
}