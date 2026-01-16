using System.Domain.Models;
using System.Text;

namespace System.Domain.Services;

public class ReportGenerator
{
    public void Generate(IEnumerable<Vulnerability> vulnerabilities, bool compliant, AuditSignature? signature = null)
    {
        var vulnList = vulnerabilities.ToList();

        // 1. TERMINAL HEADER
        Console.WriteLine("\n" + new string('=', 70));
        Console.WriteLine("        CRA SECURITY AUDIT: ENTERPRISE DASHBOARD v1.2");
        Console.WriteLine(new string('=', 70));

        if (!vulnList.Any())
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  [OK] No vulnerabilities found. Compliance Satisfied.");
            Console.ResetColor();
        }
        else
        {
            // 2. VISUAL ALERTS
            foreach (var v in vulnList)
            {
                ApplyConsoleColor(v);
                string zoneLabel = v.ComponentZone == TrustZone.InternetFacing ? "[!] INTERNET-FACING" : "[i] Internal";
                Console.WriteLine($"- [{v.Severity.ToUpper()}] {v.Id} | {zoneLabel}");
                Console.ResetColor();
            }

            // 3. DETAILED EVIDENCE TABLE
            Console.WriteLine("\nDETAILED REGULATORY EVIDENCE:");
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

        // 4. W41 IDENTITY OVERRIDE DISPLAY
        if (signature != null)
        {
            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.Blue;
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($" [W41 AUTHENTICATED OVERRIDE] ");
            Console.WriteLine($" Officer: {signature.OfficerName} ({signature.SignedAt:yyyy-MM-dd})");
            Console.WriteLine($" Reason:  {signature.Reason} ");
            Console.ResetColor();
        }

        // 5. COMPLIANCE VERDICT
        Console.WriteLine("\n=== CRA COMPLIANCE RESULT ===");
        if (compliant)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(signature != null ? ">>> STATUS: PASS (BY AUTHORIZED OVERRIDE) ✅" : ">>> STATUS: PASS ✅");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(">>> STATUS: FAIL ❌");
        }
        Console.ResetColor();
        Console.WriteLine(new string('=', 70));
        
        GenerateMarkdownReport(vulnList, compliant, signature);
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

    private void GenerateMarkdownReport(List<Vulnerability> vulns, bool compliant, AuditSignature? signature)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Cyber Resilience Act (CRA) Compliance Report");
        sb.AppendLine($"**Generated:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"**Final Verdict:** {(compliant ? "PASS" : "FAIL")}");
        
        if (signature != null)
        {
            sb.AppendLine("\n## W41 Identity Exception");
            sb.AppendLine($"- **Approved By:** {signature.OfficerName}");
            sb.AppendLine($"- **Reason:** {signature.Reason}");
            sb.AppendLine($"- **Session Thumbprint:** {signature.OAuthTokenThumbprint}");
        }

        sb.AppendLine("\n## Summary");
        sb.AppendLine($"- Total Vulnerabilities: {vulns.Count}");
        
        sb.AppendLine("\n## Detailed Evidence Table");
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