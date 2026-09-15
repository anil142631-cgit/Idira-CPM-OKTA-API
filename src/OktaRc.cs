// ---------------------------------------------------------------------------
//  File    : OktaRc.cs
//  Project : Okta API Token CPM Plugin (OktaApiTokenPlugin.dll) - Option A on the .NET SDK
//  Purpose : Plugin return codes and exception type
//  Author  : Anilkumar Dadi | Anilkumar.Dadi@cyderes.com | Cyderes
//  Version : 1.0
//  Date    : 15-Sep-2026
// ---------------------------------------------------------------------------
using System;

namespace CyberArk.Extensions.Plugin.OktaOAuth
{
    /// <summary>
    /// Plugin return codes. CPM expects 0 for success and 8000-9000 for errors; the message set on
    /// PlatformOutput is what the operator sees in PVWA. Codes listed in the platform's
    /// UnrecoverableErrors setting are not retried; 8413 belongs in RCReconcileReasons so CPM auto-reconciles.
    /// </summary>
    internal static class OktaRc
    {
        public const int SUCCESS = 0;
        public const int CONNECTION_ERROR = 8000;     // cannot reach the Okta org (DNS, proxy, TLS, firewall)
        public const int BAD_REQUEST = 8400;          // Okta rejected the request (usually password policy on reconcile)
        public const int UNAUTHORIZED = 8401;         // access token rejected by the Users API
        public const int TOKEN_REFUSED = 8402;        // token endpoint rejected the client assertion (key, kid, client_id, scopes)
        public const int FORBIDDEN = 8403;            // app's admin role cannot manage this user
        public const int NOT_FOUND = 8404;            // login not found in the org
        public const int PASSWORD_INVALID = 8413;     // stored password is wrong (strict verify, or E0000014 "Old Password is not correct")
        public const int CHANGE_REJECTED = 8414;      // E0000014: new password violates the Okta password policy
        public const int USER_NOT_MANAGEABLE = 8420;  // not ACTIVE or not Okta-sourced
        public const int RATE_LIMITED = 8429;         // Okta API rate limit
        public const int KEY_FORMAT_ERROR = 8450;     // vaulted secret is not a usable private JWK
        public const int MISSING_PARAMETER = 8460;    // account / platform property missing
        public const int GENERAL_ERROR = 8999;
    }

    /// <summary>Carries a CPM return code plus an operator-facing message.</summary>
    internal sealed class OktaException : Exception
    {
        public int ReturnCode { get; private set; }

        public OktaException(int returnCode, string message) : base(message)
        {
            ReturnCode = returnCode;
        }

        public OktaException(int returnCode, string message, Exception inner) : base(message, inner)
        {
            ReturnCode = returnCode;
        }
    }
}
