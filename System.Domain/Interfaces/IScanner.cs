using System.Domain.Models;

namespace System.Domain.Interfaces;

public interface IScanner
{
    GrypeReport Scan(string path);
}