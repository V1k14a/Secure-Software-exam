using Microsoft.EntityFrameworkCore;

namespace System.Infrastructure.Data;

public class SecurityDbContext : DbContext
{
    public SecurityDbContext()
    {
        Database.EnsureCreated();
    }

    public DbSet<VulnerabilityRecord> History => Set<VulnerabilityRecord>();

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite("Data Source=compliance_audit.db");
    }
}

public class VulnerabilityRecord
{
    public int Id { get; set; }
    public string CVEId { get; set; } = "";
    public string Package { get; set; } = "";
    public string ExpectedHash { get; set; } = ""; // W40: Integrity check
    public DateTime FirstSeen { get; set; }
}