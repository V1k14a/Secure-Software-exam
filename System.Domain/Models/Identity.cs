using System;

namespace System.Domain.Models;

public record SecurityOfficer(string Username, string Role, string Email);

public class AuditSignature
{
    public string OfficerName { get; set; } = "";
    public string Reason { get; set; } = "";
    
    
    public string OAuthTokenThumbprint { get; set; } = ""; 
    
    public DateTime SignedAt { get; set; }
}