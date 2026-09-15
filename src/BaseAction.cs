// ---------------------------------------------------------------------------
//  File    : BaseAction.cs
//  Project : Okta API Token CPM Plugin (OktaApiTokenPlugin.dll) - Option A on the .NET SDK
//  Purpose : Shared base - reads accounts and platform settings, resolves the API token account, secret retrieval, error handling
//  Author  : Anilkumar Dadi | Anilkumar.Dadi@cyderes.com | Cyderes
//  Version : 1.0
//  Date    : 15-Sep-2026
// ---------------------------------------------------------------------------
using System;
using System.Text;
using System.Collections.Generic;
using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.Reader;

namespace CyberArk.Extensions.Plugin.OktaOAuth
{
    /// <summary>Everything an action needs, resolved from the accounts CPM hands to the plugin.</summary>
    internal sealed class OktaContext
    {
        public string OrgHostname;        // target account Address, e.g. dev-123456.okta.com
        public string TargetLogin;        // target account Username, e.g. bg-admin@lab.test
        public string ClientId;           // credential account Username = Okta app client_id
        public string PrivateJwk;         // credential account secret = the Okta API token
        public string Scopes;             // platform: OktaScopes
        public bool RevokeSessions;       // platform: RevokeSessionsOnChange
        public bool StrictVerify;         // platform: StrictVerify (POST /api/v1/authn with the target's password)
        public int AssertionLifetime;     // platform: AssertionLifetimeSeconds
        public int HttpTimeout;           // platform: HttpTimeoutSeconds
    }

    /// <summary>
    /// Shared plumbing for all actions. Follows the CyberArk .NET SDK template: the constructor
    /// signature must not change, and ParametersAPI is the SDK's ParametersManager.
    /// </summary>
    public abstract class BaseAction : AbsAction
    {
        internal ParametersManager ParametersAPI { get; private set; }

        /// <summary>The SDK's TargetAccount is protected; expose it to the helper classes in this assembly.</summary>
        internal TargetAccount Target { get { return TargetAccount; } }
        private readonly List<IAccount> _accounts;
        private bool _lastRoleIsReconcile;
        private bool _diagnosticsDone;
        private int _preferredExtraPassIndex = 1;

        protected BaseAction(List<IAccount> accountList, ILogger logger) : base(accountList, logger)
        {
            ParametersAPI = new ParametersManager();
            _accounts = accountList ?? new List<IAccount>();
        }

        /// <summary>
        /// Builds the context using the given credential account (LogOnAccount for verify/change/logon,
        /// ReconcileAccount for reconcile/prereconcile - both ExtraPassAccount in this SDK). The private
        /// key is read from that account's current password.
        /// </summary>
        internal OktaContext BuildContext(string credentialRole)
        {
            ExtraPassAccount credentialAccount = PickCredentialAccount(credentialRole);
            if (credentialAccount == null)
                throw new OktaException(OktaRc.MISSING_PARAMETER,
                    "No linked account carries the Okta OAuth app key. Link the app-key account as the " + credentialRole + " account of the target.");

            var ctx = new OktaContext
            {
                OrgHostname = ParametersAPI.GetMandatoryParameter("address", TargetAccount.AccountProp),
                TargetLogin = ParametersAPI.GetMandatoryParameter("username", TargetAccount.AccountProp),
                ClientId = ParametersAPI.GetMandatoryParameter("username", credentialAccount.AccountProp),
                PrivateJwk = ReadSecret(credentialAccount, false),
                Scopes = GetSetting("OktaScopes", "okta.users.manage okta.users.read"),
                RevokeSessions = IsYes(GetSetting("RevokeSessionsOnChange", "Yes")),
                StrictVerify = IsYes(GetSetting("StrictVerify", "No")),
                AssertionLifetime = ToInt(GetSetting("AssertionLifetimeSeconds", "300"), 300),
                HttpTimeout = ToInt(GetSetting("HttpTimeoutSeconds", "30"), 30)
            };

            Logger.WriteLine("Okta org=" + ctx.OrgHostname + " target=" + ctx.TargetLogin + " credential=" + (OktaApiClient.IsApiToken(ctx.PrivateJwk) ? "API token (SSWS) owner " : "client ") + ctx.ClientId +
                             " credential role=" + credentialRole, LogLevel.INFO);
            return ctx;
        }


        /// <summary>
        /// The SDK exposes three linked-account slots (LogOnAccount, Extrapass2Account, ReconcileAccount) and
        /// the slot that is populated depends on how the plugin is invoked. Prefer the slot that matches the role, then
        /// fall back to any other slot that actually carries an account, and log what was found.
        /// </summary>
        internal ExtraPassAccount PickCredentialAccount(string credentialRole)
        {
            Logger.WriteLine("Linked accounts -> LogOnAccount=" + Describe(LogOnAccount) +
                             " Extrapass2Account=" + Describe(Extrapass2Account) +
                             " ReconcileAccount=" + Describe(ReconcileAccount), LogLevel.INFO);

            bool reconcile = string.Equals(credentialRole, "Reconcile", StringComparison.OrdinalIgnoreCase);
            _lastRoleIsReconcile = reconcile;
            ExtraPassAccount[] order = reconcile
                ? new ExtraPassAccount[] { ReconcileAccount, LogOnAccount, Extrapass2Account }
                : new ExtraPassAccount[] { LogOnAccount, ReconcileAccount, Extrapass2Account };

            foreach (ExtraPassAccount a in order)
                if (a != null && a.AccountProp != null && a.AccountProp.Count > 0) return a;

            // The SDK properties were empty: look at the raw list the invoker/CPM handed to the constructor.
            var sb = new System.Text.StringBuilder();
            foreach (IAccount acc in _accounts)
                sb.Append(acc == null ? "null" : acc.GetType().Name + "#" + acc.Index).Append(' ');
            Logger.WriteLine("Raw account list (" + _accounts.Count + "): " + sb, LogLevel.INFO);

            int preferredIndex = reconcile ? 3 : 1;
            _preferredExtraPassIndex = preferredIndex;
            ExtraPassAccount byIndex = null;
            var extras = new List<ExtraPassAccount>();
            foreach (IAccount acc in _accounts)
            {
                ExtraPassAccount e = acc as ExtraPassAccount;
                if (e == null || e.AccountProp == null || e.AccountProp.Count == 0) continue;
                if (e.Index == preferredIndex) byIndex = e;
                extras.Add(e);
            }
            if (byIndex != null) return byIndex;
            // Indexes are all 0 in this SDK build; the invoker assigns the logon account first and the
            // reconcile account second, so fall back to list position.
            if (extras.Count == 0) return null;
            if (reconcile && extras.Count > 1) return extras[extras.Count - 1];
            return extras[0];
        }

        private static string Describe(ExtraPassAccount a)
        {
            if (a == null) return "null";
            if (a.AccountProp == null) return "index=" + a.Index + " (no properties)";
            string user;
            foreach (KeyValuePair<string, string> kv in a.AccountProp)
                if (string.Equals(kv.Key, "username", StringComparison.OrdinalIgnoreCase)) { user = kv.Value; return "index=" + a.Index + " username=" + user; }
            return "index=" + a.Index + " keys=" + a.AccountProp.Count;
        }


        /// <summary>
        /// Secrets come from the SDK's SecureString when the CPM runs the plugin. In CANetPluginInvoker runs the
        /// SecureString is empty and the ini's password= / newpassword= values sit in the property bag instead,
        /// so fall back to those. Never logs the value.
        /// </summary>
        internal string ReadSecret(BaseAccount account, bool newPassword)
        {
            if (account == null) return null;

            // The invoker serialises accounts into this AppDomain and the SDK's PluginsRunner normally calls
            // RetrieveAfterTransfer() to rebuild the SecureString from the encrypted byte[] carried over the
            // boundary. Call it here too - it is idempotent - so the password is present regardless.
            System.Security.SecureString ss = GetSecure(account, newPassword);
            if (ss == null || ss.Length == 0)
            {
                try { account.RetrieveAfterTransfer(); }
                catch (Exception ex) { Logger.WriteLine("RetrieveAfterTransfer threw: " + ex.GetType().Name + " - " + ex.Message, LogLevel.INFO); }
                ss = GetSecure(account, newPassword);
            }

            if (ss != null && ss.Length > 0) return ss.convertSecureStringToString();

            // Invoker manual mode (CANetPluginInvoker with an ini) keeps the value in the property bag.
            string prop = newPassword ? "newpassword" : "password";
            string fromProps = Lookup(account.AccountProp, prop);
            if (!string.IsNullOrEmpty(fromProps))
            {
                Logger.WriteLine("Secret '" + prop + "' taken from account properties (invoker mode)", LogLevel.INFO);
                return fromProps;
            }

            LogDeepDiagnostics(account);
            return null;
        }

        private static System.Security.SecureString GetSecure(BaseAccount account, bool newPassword)
        {
            if (newPassword)
            {
                TargetAccount tg = account as TargetAccount;
                return tg != null ? tg.NewPassword : null;
            }
            return account.CurrentPassword;
        }

        private string ReadSecretFromEnvironment(BaseAccount account, bool newPassword)
        {
            string[] names;
            if (account is TargetAccount)
                names = newPassword ? new[] { "pmnewpass" } : new[] { "pmpass" };
            else if (_preferredExtraPassIndex == 3)
                names = new[] { "pmextrapass3", "pmextrapass1", "pmextrapass2" };
            else
                names = new[] { "pmextrapass1", "pmextrapass3", "pmextrapass2" };

            foreach (string n in names)
            {
                string v = Environment.GetEnvironmentVariable(n);
                if (!string.IsNullOrEmpty(v))
                {
                    Logger.WriteLine("Secret taken from environment variable " + n, LogLevel.INFO);
                    return v;
                }
            }
            return null;
        }

        private static string PmEnvironmentSummary()
        {
            var sb = new System.Text.StringBuilder();
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
            {
                string k = e.Key as string;
                if (k != null && k.StartsWith("pm", StringComparison.OrdinalIgnoreCase))
                    sb.Append(k).Append('=').Append(e.Value == null ? 0 : e.Value.ToString().Length).Append(' ');
            }
            return sb.Length == 0 ? "(none)" : sb.ToString();
        }

        private static string FieldSummary(object o)
        {
            var sb = new System.Text.StringBuilder();
            foreach (System.Reflection.FieldInfo f in o.GetType().GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.FlattenHierarchy))
            {
                object v = null; string desc;
                try { v = f.GetValue(o); } catch (Exception) { }
                if (v == null) desc = "null";
                else if (v is System.Security.SecureString) desc = "SecureString(" + ((System.Security.SecureString)v).Length + ")";
                else if (v is string) desc = "string(" + ((string)v).Length + ")";
                else if (v is System.Collections.ICollection) desc = v.GetType().Name + "[" + ((System.Collections.ICollection)v).Count + "]";
                else desc = v.GetType().Name;
                sb.Append(f.Name).Append(':').Append(desc).Append(' ');
            }
            return sb.ToString();
        }


        /// <summary>
        /// One-off diagnostics when no secret could be found: environment variable names that look like CPM
        /// secrets, and every field of the account objects with its type and length. Values are never logged.
        /// </summary>
        private void LogDeepDiagnostics(BaseAccount credentialAccount)
        {
            if (_diagnosticsDone) return;
            _diagnosticsDone = true;
            try
            {
                var env = new System.Text.StringBuilder();
                foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
                {
                    string k = e.Key.ToString();
                    if (k.StartsWith("pm", StringComparison.OrdinalIgnoreCase) || k.IndexOf("pass", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        k.IndexOf("cyberark", StringComparison.OrdinalIgnoreCase) >= 0)
                        env.Append(k).Append('=').Append(e.Value == null ? 0 : e.Value.ToString().Length).Append(' ');
                }
                Logger.WriteLine("DIAG env (name=length): " + env, LogLevel.INFO);

                DumpFields("DIAG credential account", credentialAccount);
                DumpFields("DIAG target account", TargetAccount);
                DumpFields("DIAG action base", this, typeof(AbsAction));
            }
            catch (Exception ex)
            {
                Logger.WriteLine("DIAG failed: " + ex.Message, LogLevel.WARNING);
            }
        }

        private void DumpFields(string label, object obj, Type asType = null)
        {
            if (obj == null) { Logger.WriteLine(label + ": null", LogLevel.INFO); return; }
            Type type = asType ?? obj.GetType();
            var sb = new System.Text.StringBuilder();
            sb.Append(label).Append(" [").Append(type.Name).Append("]: ");
            while (type != null && type != typeof(object))
            {
                foreach (System.Reflection.FieldInfo f in type.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.DeclaredOnly))
                {
                    object v = null;
                    try { v = f.GetValue(obj); } catch (Exception) { }
                    sb.Append(f.Name).Append(':').Append(f.FieldType.Name).Append('=').Append(Summarize(v)).Append(' ');
                }
                type = type.BaseType;
            }
            Logger.WriteLine(sb.ToString(), LogLevel.INFO);
        }

        private static string Summarize(object v)
        {
            if (v == null) return "null";
            var ss = v as System.Security.SecureString;
            if (ss != null) return "SecureString(" + ss.Length + ")";
            var str = v as string;
            if (str != null) return "string(" + str.Length + ")";
            var dict = v as System.Collections.IDictionary;
            if (dict != null)
            {
                var keys = new System.Text.StringBuilder();
                foreach (object k in dict.Keys) keys.Append(k).Append(',');
                return "dict{" + keys + "}";
            }
            var list = v as System.Collections.ICollection;
            if (list != null) return "collection(" + list.Count + ")";
            return v.GetType().Name;
        }

        internal OktaApiClient CreateClient(OktaContext ctx)
        {
            return new OktaApiClient(ctx.OrgHostname, ctx.HttpTimeout, s => Logger.WriteLine(s, LogLevel.INFO));
        }

        /// <summary>Platform (extrainfo) setting with a default; the target account can override it.</summary>
        internal string GetSetting(string name, string defaultValue)
        {
            string v = Lookup(TargetAccount.AccountProp, name) ?? Lookup(TargetAccount.ExtraInfoProp, name);
            return string.IsNullOrWhiteSpace(v) ? defaultValue : v.Trim();
        }

        private static string Lookup(Dictionary<string, string> dict, string name)
        {
            if (dict == null) return null;
            foreach (var kv in dict)
                if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
            return null;
        }

        private static bool IsYes(string v)
        {
            return string.Equals(v, "yes", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(v, "true", StringComparison.OrdinalIgnoreCase) || v == "1";
        }

        internal static int ToInt(string v, int fallback)
        {
            int n;
            return int.TryParse(v, out n) && n > 0 ? n : fallback;
        }

        /// <summary>Uniform failure handling: known Okta errors keep their code, anything else is the SDK default.</summary>
        internal int Fail(Exception ex, ref PlatformOutput platformOutput)
        {
            var oex = ex as OktaException;
            if (oex != null)
            {
                Logger.WriteLine("Action failed (" + oex.ReturnCode + "): " + oex.Message, LogLevel.ERROR);
                platformOutput.Message = oex.Message;
                return oex.ReturnCode;
            }
            return HandleGeneralError(ex, ref platformOutput);
        }

        internal int HandleGeneralError(Exception ex, ref PlatformOutput platformOutput)
        {
            // This SDK build has no PluginErrors dictionary; report the exception plainly with the general code.
            Logger.WriteLine(string.Format("Received exception: {0}.", ex), LogLevel.ERROR);
            platformOutput.Message = "Okta plugin failed unexpectedly: " + ex.GetType().Name + " - " + ex.Message;
            return OktaRc.GENERAL_ERROR;
        }
    }
}
