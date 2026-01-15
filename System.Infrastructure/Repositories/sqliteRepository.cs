namespace System.Infrastructure.Repositories;
using System.Domain.Interfaces;
using System.Infrastructure.Data;

public class SqliteRepository : ISecurityRepository 
{
    public DateTime? GetHistoryById(string id, string package) 
    {
        using var db = new SecurityDbContext();
        return db.History.FirstOrDefault(h => h.CVEId == id && h.Package == package)?.FirstSeen;
    }

    public DateTime SaveNewDiscovery(string id, string package) 
    {
        using var db = new SecurityDbContext();
        var now = DateTime.Now;
        db.History.Add(new VulnerabilityRecord { CVEId = id, Package = package, FirstSeen = now });
        db.SaveChanges();
        return now;
    }
}