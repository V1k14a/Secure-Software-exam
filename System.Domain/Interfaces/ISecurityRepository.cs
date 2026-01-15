namespace System.Domain.Interfaces;

public interface ISecurityRepository 
{ 
    DateTime? GetHistoryById(string id, string package); 
    DateTime SaveNewDiscovery(string id, string package); 
}