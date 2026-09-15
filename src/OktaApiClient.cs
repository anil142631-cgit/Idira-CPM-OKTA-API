// ---------------------------------------------------------------------------
//  File    : OktaApiClient.cs
//  Project : Okta API Token CPM Plugin (OktaApiTokenPlugin.dll) - Option A on the .NET SDK
//  Purpose : Okta HTTP client - Users API calls with an Okta API token (SSWS) and error mapping to CPM return codes
//  Author  : Anilkumar Dadi | Anilkumar.Dadi@cyderes.com | Cyderes
//  Version : 1.0
//  Date    : 15-Sep-2026
// ---------------------------------------------------------------------------
using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Web.Script.Serialization;

namespace CyberArk.Extensions.Plugin.OktaOAuth
{
    /// <summary>Minimal view of an Okta user as needed by the plugin.</summary>
    internal sealed class OktaUser
    {
        public string Id;
        public string Login;
        public string Status;
        public string CredentialProvider;

        public bool IsManageable
        {
            get
            {
                bool statusOk = string.Equals(Status, "ACTIVE", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(Status, "PASSWORD_EXPIRED", StringComparison.OrdinalIgnoreCase);
                return statusOk && string.Equals(CredentialProvider, "OKTA", StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>
    /// All Okta traffic for the plugin. One instance per CPM action.
    /// Authentication: Okta API token (SSWS) held in the Vault as the linked logon/reconcile account.
    /// </summary>
    internal sealed class OktaApiClient : IDisposable
    {
        private const string TokenPath = "/oauth2/v1/token";
        private readonly string _baseUrl;
        private readonly HttpClient _http;
        private readonly Action<string> _log;
        private readonly JavaScriptSerializer _json = new JavaScriptSerializer();

        public OktaApiClient(string orgHostname, int timeoutSeconds, Action<string> log)
        {
            if (string.IsNullOrWhiteSpace(orgHostname))
                throw new OktaException(OktaRc.MISSING_PARAMETER, "The account's Address (Okta org hostname) is empty.");

            string host = orgHostname.Trim();
            if (host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                host.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                host = host.Substring(host.IndexOf("://", StringComparison.Ordinal) + 3);
            _baseUrl = "https://" + host.TrimEnd('/');

            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds <= 0 ? 30 : timeoutSeconds) };
            _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("CyberArk-CPM-OktaOAuth/1.0");
            _log = log ?? (s => { });
        }

        public string TokenEndpoint { get { return _baseUrl + TokenPath; } }

        // ------------------------------------------------------------------------------------------
        // OAuth: client assertion -> access token
        // ------------------------------------------------------------------------------------------

        /// <summary>
        /// Option A: the linked credential account holds an Okta API token. There is no token exchange - the API
        /// token itself is the authorization, sent as "Authorization: SSWS <token>" on every call.
        /// </summary>
        public string GetAccessToken(string clientId, string apiToken, string scopes, int assertionLifetimeSeconds)
        {
            if (string.IsNullOrWhiteSpace(apiToken))
                throw new OktaException(OktaRc.KEY_FORMAT_ERROR, "The credential account's secret is empty; it must contain the Okta API token.");
            if (!IsApiToken(apiToken))
                throw new OktaException(OktaRc.KEY_FORMAT_ERROR, "The credential account's secret is not an Okta API token (expected the 42-character value starting with 00).");
            _log("Credential is an Okta API token (SSWS) - calling the Users API with it directly");
            return SswsAuthorization(apiToken);
        }

        // ------------------------------------------------------------------------------------------
        // Users API
        // ------------------------------------------------------------------------------------------

        public OktaUser GetUser(string accessToken, string login)
        {
            string url = _baseUrl + "/api/v1/users/" + Uri.EscapeDataString(login);
            HttpResponseMessage resp = Send(() => _http.SendAsync(Request(HttpMethod.Get, url, accessToken, null)));
            string body = ReadBody(resp);
            EnsureSuccess(resp, body, login, "look up user");

            var u = ParseObject(body);
            var creds = Obj(u, "credentials");
            var provider = creds != null ? Obj(creds, "provider") : null;
            var profile = Obj(u, "profile");
            var user = new OktaUser
            {
                Id = Str(u, "id"),
                Login = profile != null ? Str(profile, "login") : login,
                Status = Str(u, "status"),
                CredentialProvider = provider != null ? Str(provider, "type") : null
            };
            _log("User " + user.Login + " id=" + user.Id + " status=" + user.Status + " provider=" + user.CredentialProvider);
            return user;
        }

        /// <summary>Change: Okta validates the old password and enforces the password policy.</summary>
        public void ChangePassword(string accessToken, string userId, string oldPassword, string newPassword, bool revokeSessions)
        {
            string url = _baseUrl + "/api/v1/users/" + userId + "/credentials/change_password";
            var payload = new Dictionary<string, object>
            {
                { "oldPassword", new Dictionary<string, object> { { "value", oldPassword } } },
                { "newPassword", new Dictionary<string, object> { { "value", newPassword } } },
                { "revokeSessions", revokeSessions }
            };
            HttpResponseMessage resp = Send(() => _http.SendAsync(Request(HttpMethod.Post, url, accessToken, _json.Serialize(payload))));
            string body = ReadBody(resp);
            EnsureSuccess(resp, body, userId, "change the password of");
        }

        /// <summary>Reconcile: admin-set via partial update; no old password required.</summary>
        public void SetPassword(string accessToken, string userId, string newPassword)
        {
            string url = _baseUrl + "/api/v1/users/" + userId;
            var payload = new Dictionary<string, object>
            {
                { "credentials", new Dictionary<string, object>
                    { { "password", new Dictionary<string, object> { { "value", newPassword } } } } }
            };
            HttpResponseMessage resp = Send(() => _http.SendAsync(Request(HttpMethod.Post, url, accessToken, _json.Serialize(payload))));
            string body = ReadBody(resp);
            EnsureSuccess(resp, body, userId, "reconcile the password of");
        }

        /// <summary>
        /// Optional strict verify: primary authentication with the target's own credentials (no access token).
        /// Returns the transaction status. Wrong password -> PASSWORD_INVALID. Counts as a sign-in attempt in Okta.
        /// </summary>
        public string PrimaryAuthStatus(string login, string password)
        {
            string url = _baseUrl + "/api/v1/authn";
            var payload = new Dictionary<string, object> { { "username", login }, { "password", password } };
            var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(_json.Serialize(payload), Encoding.UTF8, "application/json")
            };
            HttpResponseMessage resp = Send(() => _http.SendAsync(req));
            string body = ReadBody(resp);
            var obj = ParseObject(body);

            if ((int)resp.StatusCode == 401 && string.Equals(Str(obj, "errorCode"), "E0000004", StringComparison.OrdinalIgnoreCase))
                throw new OktaException(OktaRc.PASSWORD_INVALID, "Okta authentication failed for " + login + ": the stored password is wrong. Run Reconcile.");
            if ((int)resp.StatusCode == 429)
                throw new OktaException(OktaRc.RATE_LIMITED, "Okta API rate limit reached during verify. Safe to retry later.");
            if (!resp.IsSuccessStatusCode)
                throw new OktaException(OktaRc.GENERAL_ERROR, "Unexpected response from /api/v1/authn for " + login + " (" +
                    (int)resp.StatusCode + " " + Str(obj, "errorCode") + ": " + Str(obj, "errorSummary") + "). On Identity Engine orgs strict verify may be unsupported - set StrictVerify=No.");

            string status = Str(obj, "status");
            _log("Primary authentication for " + login + " returned status " + status);
            return status ?? "";
        }

        // ------------------------------------------------------------------------------------------
        // plumbing
        // ------------------------------------------------------------------------------------------

        /// <summary>True when the secret is an Okta API token (SSWS) rather than an OAuth key or seed.</summary>
        public static bool IsApiToken(string secret)
        {
            return !string.IsNullOrEmpty(secret) && System.Text.RegularExpressions.Regex.IsMatch(secret.Trim(), "^00[A-Za-z0-9_\\-]{40}$");
        }

        /// <summary>Authorization value for an API token; passed wherever an access token is expected.</summary>
        public static string SswsAuthorization(string apiToken) { return "SSWS " + apiToken.Trim(); }

        private static HttpRequestMessage Request(HttpMethod method, string url, string accessToken, string jsonBody)
        {
            var req = new HttpRequestMessage(method, url);
            req.Headers.Authorization = accessToken != null && accessToken.StartsWith("SSWS ")
                ? new AuthenticationHeaderValue("SSWS", accessToken.Substring(5))
                : new AuthenticationHeaderValue("Bearer", accessToken);
            if (jsonBody != null)
                req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            return req;
        }

        private HttpResponseMessage Send(Func<System.Threading.Tasks.Task<HttpResponseMessage>> call)
        {
            try
            {
                return call().GetAwaiter().GetResult();
            }
            catch (HttpRequestException ex)
            {
                throw new OktaException(OktaRc.CONNECTION_ERROR, "Cannot reach " + _baseUrl + ": " + Root(ex).Message, ex);
            }
            catch (System.Threading.Tasks.TaskCanceledException ex)
            {
                throw new OktaException(OktaRc.CONNECTION_ERROR, "Timed out talking to " + _baseUrl + ".", ex);
            }
        }

        private static string ReadBody(HttpResponseMessage resp)
        {
            return resp.Content == null ? string.Empty : resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        }

        /// <summary>Maps Okta's HTTP status + errorCode to a CPM return code with an operator-readable message.</summary>
        private void EnsureSuccess(HttpResponseMessage resp, string body, string subject, string verb)
        {
            if (resp.IsSuccessStatusCode) return;

            var err = ParseObject(body);
            string code = Str(err, "errorCode");
            string summary = Str(err, "errorSummary");
            string cause = FirstCause(err);
            string detail = (code ?? ((int)resp.StatusCode).ToString()) + ": " + (summary ?? resp.ReasonPhrase) +
                            (string.IsNullOrEmpty(cause) ? "" : " - " + cause);
            _log("Okta refused to " + verb + " " + subject + " (" + detail + ")");

            switch ((int)resp.StatusCode)
            {
                case 400:
                    throw new OktaException(OktaRc.BAD_REQUEST, "Okta rejected the request to " + verb + " " + subject + " (" + detail +
                        "). If this mentions password requirements, align the platform password policy with the Okta password policy.");
                case 401:
                    throw new OktaException(OktaRc.UNAUTHORIZED, "Okta rejected the access token while trying to " + verb + " " + subject + " (" + detail + ").");
                case 403:
                    if (string.Equals(code, "E0000014", StringComparison.OrdinalIgnoreCase))
                    {
                        string why = cause ?? summary ?? "";
                        if (why.IndexOf("old password", StringComparison.OrdinalIgnoreCase) >= 0)
                            throw new OktaException(OktaRc.PASSWORD_INVALID, "Okta rejected the password change for " + subject +
                                ": the stored password is wrong (" + why + "). Run Reconcile.");
                        throw new OktaException(OktaRc.CHANGE_REJECTED, "Okta rejected the password update for " + subject + ": " + why +
                            ". Align the platform password policy with the Okta password policy (length, complexity, history, minimum age).");
                    }
                    throw new OktaException(OktaRc.FORBIDDEN, "Okta refused to " + verb + " " + subject + " (" + detail +
                        "). The app's admin role cannot manage this user - admins can only be managed by a Super Admin.");
                case 404:
                    throw new OktaException(OktaRc.NOT_FOUND, "Okta user " + subject + " was not found in " + _baseUrl + " (" + detail + ").");
                case 429:
                    throw new OktaException(OktaRc.RATE_LIMITED, "Okta API rate limit reached (" + detail + "). Safe to retry later.");
                default:
                    throw new OktaException(OktaRc.GENERAL_ERROR, "Unexpected response from Okta while trying to " + verb + " " + subject + " (" + detail + ").");
            }
        }

        private Dictionary<string, object> ParseObject(string body)
        {
            if (string.IsNullOrWhiteSpace(body)) return new Dictionary<string, object>();
            try
            {
                return _json.Deserialize<Dictionary<string, object>>(body) ?? new Dictionary<string, object>();
            }
            catch
            {
                return new Dictionary<string, object> { { "errorSummary", Truncate(body, 200) } };
            }
        }

        private static string FirstCause(Dictionary<string, object> err)
        {
            object causes;
            if (err == null || !err.TryGetValue("errorCauses", out causes) || causes == null) return null;
            var list = causes as IEnumerable;
            if (list == null) return null;
            foreach (object item in list)
            {
                var d = item as Dictionary<string, object>;
                if (d != null) return Str(d, "errorSummary");
            }
            return null;
        }

        private static Dictionary<string, object> Obj(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) ? v as Dictionary<string, object> : null;
        }

        private static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v != null ? v.ToString() : null;
        }

        private static Exception Root(Exception ex)
        {
            while (ex.InnerException != null) ex = ex.InnerException;
            return ex;
        }

        private static string Truncate(string s, int max)
        {
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }

        public void Dispose()
        {
            _http.Dispose();
        }
    }
}
