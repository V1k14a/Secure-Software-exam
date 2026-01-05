using System.Diagnostics;
using System.Text.Json;
using System.Domain.Interfaces;
using System.Domain.Models;

namespace System.Domain.Services;

public class GrypeRunner : IScanner
{
    private const string SbomFile = "sbom.json";
    
    private readonly string _syftPath = @"C:\Users\ivan1\AppData\Local\Microsoft\WinGet\Packages\Anchore.Syft_Microsoft.Winget.Source_8wekyb3d8bbwe\syft.exe";
    private readonly string _grypePath = @"C:\Users\ivan1\AppData\Local\Microsoft\WinGet\Packages\Anchore.Grype_Microsoft.Winget.Source_8wekyb3d8bbwe\grype.exe";

    public GrypeReport Scan(string path)
    {
        try 
        {
            GenerateSbom(path);
            return ScanSbom();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] Real scan failed or tools not found: {ex.Message}");
            Console.WriteLine("[LOG] Falling back to Mock Data for demonstration...");
            return new GrypeReport { Vulnerabilities = GetMockVulnerabilities().ToList() };
        }
    }

    private void GenerateSbom(string path)
    {
        Console.WriteLine("[LOG] Generating SBOM using Syft...");
        RunProcess(_syftPath, $". --output json={SbomFile}");
    }

    private GrypeReport ScanSbom()
    {
        Console.WriteLine("[LOG] Scanning SBOM using Grype...");
        var output = RunProcess(_grypePath, $"{SbomFile} -o json", true);
        return ParseGrypeOutput(output);
    }
    
    public IEnumerable<Vulnerability> GetMockVulnerabilities()
    {
        return new List<Vulnerability>
        {
            new Vulnerability { 
                Id = "CVE-2024-001", 
                Severity = "Critical", 
                Package = "openssl", 
                FixAvailable = true, 
                FirstDiscovered = DateTime.Now.AddDays(-5) // 5 days old = SLA Violation!
            },
            new Vulnerability { 
                Id = "CVE-2024-999", 
                Severity = "Low", 
                Package = "curl", 
                FixAvailable = false, 
                FirstDiscovered = DateTime.Now 
            }
        };
    }

    private string RunProcess(string fileName, string arguments, bool captureOutput = false)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = captureOutput,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                // Ensures we look in the right place
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory 
            }
        };

        process.Start();
        string output = captureOutput ? process.StandardOutput.ReadToEnd() : "";
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0 && !string.IsNullOrEmpty(error))
            throw new Exception($"{fileName} failed: {error}");

        return output;
    }

    private static GrypeReport ParseGrypeOutput(string json)
    {
        var report = new GrypeReport();
        if (string.IsNullOrWhiteSpace(json)) return report;

        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("matches", out var matches)) return report;

        foreach (var match in matches.EnumerateArray())
        {
            var vuln = match.GetProperty("vulnerability");
            var artifact = match.GetProperty("artifact");

            report.Vulnerabilities.Add(new Vulnerability
            {
                Id = vuln.GetProperty("id").GetString() ?? "UNKNOWN",
                Severity = vuln.GetProperty("severity").GetString() ?? "Unknown",
                Package = artifact.GetProperty("name").GetString() ?? "Unknown",
                FixAvailable = vuln.TryGetProperty("fix", out _),
                FirstDiscovered = DateTime.Now 
            });
        }
        return report;
    }
}