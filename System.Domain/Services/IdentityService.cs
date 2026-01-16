using System.Domain.Models;

namespace System.Domain.Services;

public class IdentityService
{
    /// <summary>
    /// W41 Identity & Access Management:
    /// Validates a bearer token. In production, this would use Microsoft.IdentityModel
    /// to verify the JWT signature against the Agramkow Identity Provider's public keys.
    /// </summary>
    /// <param name="token">The OIDC Token provided by the user.</param>
    /// <param name="officer">The resulting identity if authorized.</param>
    /// <returns>True if the token is valid and the user has the 'Admin' role.</returns>
    public bool IsAuthorized(string token, out SecurityOfficer? officer)
    {
        // For the Exam Demo: Use the secret token to simulate a successful SSO login.
        if (token == "OIDC-TOKEN-ADMIN-SECRET")
        {
            // We simulate extracting 'Claims' from the JWT: Name, Role, and Email.
            officer = new SecurityOfficer(
                Username: "Ivan_Security_Lead", 
                Role: "SecurityAdmin", 
                Email: "i.ivan@agramkow.com"
            );
            return true;
        }

        // Return false for any other input (Zero Trust approach)
        officer = null;
        return false;
    }
}