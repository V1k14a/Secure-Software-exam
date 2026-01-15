using System.Domain.Interfaces;
using System.Infrastructure.Data;

namespace System.Infrastructure.Repositories;

public class SqliteRepository : ISecurityRepository
{
    public string GetStoredHash(string package)
    {
        using var db = new SecurityDbContext();
        return db.History
            .Where(h => h.Package == package)
            .Select(h => h.ExpectedHash)
            .FirstOrDefault() ?? "";
    }

    public DateTime? GetHistoryById(string id, string package)
    {
        using var db = new SecurityDbContext();
        return db.History
            .FirstOrDefault(h => h.CVEId == id && h.Package == package)?.FirstSeen;
    }

    public DateTime SaveNewDiscovery(string id, string package, string hash)
    {
        using var db = new SecurityDbContext();
        var now = DateTime.Now;
        db.History.Add(new VulnerabilityRecord 
        { 
            CVEId = id, 
            Package = package, 
            ExpectedHash = hash, 
            FirstSeen = now 
        });
        db.SaveChanges();
        return now;
    }
}