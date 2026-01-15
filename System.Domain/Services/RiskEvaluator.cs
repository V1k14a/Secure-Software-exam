using Microsoft.Extensions.Configuration;
using System.Domain.Interfaces;
using System.Domain.Models;

namespace System.Domain.Services;

public class RiskEvaluator : IRiskEvaluator
{
    private readonly IConfiguration _config;

    public RiskEvaluator(IConfiguration config)
    {
        _config = config;
    }

    public bool IsCraCompliant(List<Vulnerability> vulnerabilities)
    {
        // 1. Read policy from JSON with safe defaults
        var internalSlaHours = _config.GetValue<int>("SecurityPolicy:SlaHours:Internal", 48);
        var externalSlaHours = _config.GetValue<int>("SecurityPolicy:SlaHours:InternetFacing", 24);

        foreach (var v in vulnerabilities)
        {
            // Determine exposure context
            bool isPublic = v.ComponentZone == TrustZone.InternetFacing;
            int hourlyLimit = isPublic ? externalSlaHours : internalSlaHours;
            
            // If it's internet-facing, we treat "High" as "Critical" 
            // because the likelihood of exploitation is significantly higher.
            string effectiveSeverity = v.Severity;
            if (isPublic && v.Severity == "High")
            {
                effectiveSeverity = "Critical";
                Console.WriteLine($"[THREAT CONTEXT] Escalating {v.Id} to CRITICAL due to public exposure.");
            }
            
            // Under CRA, if a Critical bug has a fix available, it must be patched.
            if (effectiveSeverity == "Critical" && v.FixAvailable)
            {
                Console.WriteLine($"[BLOCKER] {v.Id} is Critical and has a fix available. Compliance Failed.");
                return false;
            }
            
            // We convert the hours from our config into days for the AgeInDays check.
            double ageInHours = (DateTime.Now - v.FirstDiscovered).TotalHours;

            if (effectiveSeverity == "Critical" && ageInHours >= hourlyLimit)
            {
                Console.WriteLine($"[SLA VIOLATION] {v.Id} has been open for {v.AgeInDays} days. " +
                                  $"Limit for {v.ComponentZone} is {hourlyLimit} hours.");
                return false;
            }
        }

        // If no rules were triggered, we are compliant!
        return true;
    }
}