using Microsoft.Extensions.DependencyInjection;
using System.Domain.Interfaces;
using System.Domain.Services;

// 1. Configure Dependency Injection
var serviceProvider = new ServiceCollection()
    .AddSingleton<IScanner, GrypeRunner>()
    .AddSingleton<IRiskEvaluator, RiskEvaluator>()
    .AddSingleton<ReportGenerator>()
    .BuildServiceProvider();

// 2. Start Application
Console.WriteLine(">>> CRA DEPENDENCY SENTINEL v1.0 <<<");

var scanner = serviceProvider.GetRequiredService<IScanner>();
var evaluator = serviceProvider.GetRequiredService<IRiskEvaluator>();
var reporter = serviceProvider.GetRequiredService<ReportGenerator>();

var report = scanner.Scan(Directory.GetCurrentDirectory());
bool isCompliant = evaluator.IsCraCompliant(report.Vulnerabilities);

reporter.Generate(report.Vulnerabilities, isCompliant);

// Exit code = CRA decision
return isCompliant ? 0 : 1;