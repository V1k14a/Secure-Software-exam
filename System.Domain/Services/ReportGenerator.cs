using System.Domain.Models;
using System.Text;

namespace System.Domain.Services;

public class ReportGenerator
{
    public void Generate(IEnumerable<Vulnerability> vulnerabilities, bool compliant)
    {
        var vulnList = vulnerabilities.ToList();
        
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("        CRA SECURITY AUDIT: TERMINAL DASHBOARD");
        Console.WriteLine(new string('=', 60));

        if (!vulnList.Any())
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  [OK] No vulnerabilities found.");
            Console.ResetColor();
        }
        else
        {
            foreach (var v in vulnList)
            {
                ApplyConsoleColor(v);
                string zoneLabel = v.ComponentZone == TrustZone.InternetFacing ? "[!] INTERNET-FACING" : "[i] Internal";
                Console.WriteLine($"- [{v.Severity.ToUpper()}] {v.Id} | {zoneLabel}");
                Console.ResetColor();
            }
            
            Console.WriteLine("\nDETAILED EVIDENCE TABLE:");
            string tableHeader = string.Format("| {0,-15} | {1,-10} | {2,-15} | {3,-10} |", "ID", "Severity", "Zone", "Age");
            Console.WriteLine(new string('-', tableHeader.Length));
            Console.WriteLine(tableHeader);
            Console.WriteLine(new string('-', tableHeader.Length));

            foreach (var v in vulnList)
            {
                Console.WriteLine("| {0,-15} | {1,-10} | {2,-15} | {3,-10} |", 
                    v.Id, v.Severity, v.ComponentZone, v.AgeInDays + " days");
            }
            Console.WriteLine(new string('-', tableHeader.Length));
        }
        
        Console.WriteLine("\n=== CRA COMPLIANCE RESULT ===");
        Console.ForegroundColor = compliant ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(compliant ? ">>> STATUS: PASS ✅" : ">>> STATUS: FAIL ❌");
        Console.ResetColor();
        Console.WriteLine(new string('=', 60));
        
        GenerateMarkdownReport(vulnList, compliant);
    }

    private void ApplyConsoleColor(Vulnerability v)
    {
        if (v.ComponentZone == TrustZone.InternetFacing && (v.Severity == "Critical" || v.Severity == "High"))
        {
            Console.BackgroundColor = ConsoleColor.DarkMagenta;
            Console.ForegroundColor = ConsoleColor.White;
        }
        else if (v.Severity == "Critical" || v.AgeInDays > 2)
        {
            Console.ForegroundColor = ConsoleColor.Red;
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
        }
    }

    private void GenerateMarkdownReport(List<Vulnerability> vulns, bool compliant)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Cyber Resilience Act (CRA) Compliance Report");
        sb.AppendLine($"**Generated:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"**Final Verdict:** {(compliant ? "PASS" : "FAIL")}");
        
        sb.AppendLine("\n## Summary");
        sb.AppendLine($"- Total Vulnerabilities Found: {vulns.Count}");
        sb.AppendLine($"- Critical/High Risk Issues: {vulns.Count(v => v.Severity == "Critical" || v.Severity == "High")}");
        
        sb.AppendLine("\n## Regulatory Evidence Table");
        sb.AppendLine();
        sb.AppendLine("| ID | Severity | Zone | Package | Fix Available | Age (Days) |");
        sb.AppendLine("|----|----------|------|---------|---------------|------------|");
        
        foreach (var v in vulns)
        {
            sb.AppendLine($"| {v.Id} | {v.Severity} | {v.ComponentZone} | {v.Package} | {v.FixAvailable} | {v.AgeInDays} |");
        }

        string fullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CRA_Compliance_Report.md");
        File.WriteAllText(fullPath, sb.ToString());
        
        Console.WriteLine($"\n[AUDIT] Professional report saved to: {fullPath}");
    }
}