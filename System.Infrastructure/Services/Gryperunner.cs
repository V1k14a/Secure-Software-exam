using System.Diagnostics;
using System.Text.Json;
using System.Domain.Interfaces;
using System.Domain.Models;
using Microsoft.Extensions.Configuration;

namespace System.Infrastructure.Services;

public class GrypeRunner : IScanner
{
    private readonly string _syftPath;
    private readonly string _grypePath;
    private const string SbomFile = "sbom.json";

    public GrypeRunner(IConfiguration config)
    {
        _syftPath = config["ScannerSettings:SyftPath"] ?? throw new ArgumentNullException("SyftPath missing in config");
        _grypePath = config["ScannerSettings:GrypePath"] ?? throw new ArgumentNullException("GrypePath missing in config");
    }

    public GrypeReport Scan(string path)
    {
        try 
        {
            GenerateSbom(path);
            return ScanSbom();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n[!] REAL SCAN FAILED: {ex.Message}");
            Console.WriteLine("[i] Using Mock Data for demonstration purposes...");
            
            return new GrypeReport 
            { 
                Vulnerabilities = GetMockVulnerabilities().ToList() 
            };
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

    // FIXED: This method was incomplete in your snippet
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
                FixAvailable = vuln.TryGetProperty("fix", out var fixProp) && 
                               fixProp.TryGetProperty("state", out var state) && 
                               state.GetString() == "fixed",
                FirstDiscovered = DateTime.Now 
            });
        }
        return report;
    }

    private IEnumerable<Vulnerability> GetMockVulnerabilities()
    {
        return new List<Vulnerability>
        {
            new Vulnerability { 
                Id = "CVE-2026-TEST", 
                Severity = "High", 
                Package = "Microsoft.AspNetCore.Server.Kestrel", 
                FixAvailable = true, 
                FirstDiscovered = DateTime.Now.AddDays(-5) 
            }
        };
    }
}