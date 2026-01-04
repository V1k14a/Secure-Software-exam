using System.Domain.Models;

namespace System.Domain.Interfaces;

public interface IRiskEvaluator
{
    bool IsCraCompliant(List<Vulnerability> vulnerabilities);
}