namespace System.Domain.Interfaces;

public interface ISecurityRepository 
{ 
    DateTime? GetHistoryById(string id, string package); 
    DateTime SaveNewDiscovery(string id, string package, string hash); 
    string GetStoredHash(string package); 
}