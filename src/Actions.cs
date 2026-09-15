// ---------------------------------------------------------------------------
//  File    : Actions.cs
//  Project : Okta API Token CPM Plugin (OktaApiTokenPlugin.dll) - Option A on the .NET SDK
//  Purpose : CPM actions: logon, verifypass, changepass, prereconcilepass, reconcilepass for Okta users with an API token
//  Author  : Anilkumar Dadi | Anilkumar.Dadi@cyderes.com | Cyderes
//  Version : 1.0
//  Date    : 15-Sep-2026
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.Reader;

namespace CyberArk.Extensions.Plugin.OktaOAuth
{
    // ----------------------------------------------------------------------------------------------
    // logon: CPM runs this before a Change. Proves the logon app key can mint a token.
    // ----------------------------------------------------------------------------------------------
    public class Logon : BaseAction
    {
        public Logon(List<IAccount> accountList, ILogger logger) : base(accountList, logger) { }

        public override CPMAction ActionName { get { return CPMAction.logon; } }

        public override int run(ref PlatformOutput platformOutput)
        {
            Logger.MethodStart();
            int rc = OktaRc.GENERAL_ERROR;
            try
            {
                OktaContext ctx = BuildContext("Logon");
                using (OktaApiClient okta = CreateClient(ctx))
                {
                    okta.GetAccessToken(ctx.ClientId, ctx.PrivateJwk, ctx.Scopes, ctx.AssertionLifetime);
                }
                rc = OktaRc.SUCCESS;
            }
            catch (Exception ex) { rc = Fail(ex, ref platformOutput); }
            finally { Logger.MethodEnd(); }
            return rc;
        }
    }

    // ----------------------------------------------------------------------------------------------
    // verifypass: token with the logon key, then confirm the target exists, is ACTIVE and Okta-sourced.
    // Okta has no side-effect-free "is this password right" call; change_password is the real check.
    // With StrictVerify=Yes the plugin additionally authenticates as the target (POST /api/v1/authn), so a
    // wrong stored password fails verify with 8413 and CPM can auto-reconcile (RCReconcileReasons=8413).
    // ----------------------------------------------------------------------------------------------
    public class Verify : BaseAction
    {
        public Verify(List<IAccount> accountList, ILogger logger) : base(accountList, logger) { }

        public override CPMAction ActionName { get { return CPMAction.verifypass; } }

        public override int run(ref PlatformOutput platformOutput)
        {
            Logger.MethodStart();
            int rc = OktaRc.GENERAL_ERROR;
            try
            {
                OktaContext ctx = BuildContext("Logon");
                using (OktaApiClient okta = CreateClient(ctx))
                {
                    string token = okta.GetAccessToken(ctx.ClientId, ctx.PrivateJwk, ctx.Scopes, ctx.AssertionLifetime);
                    OktaUser user = okta.GetUser(token, ctx.TargetLogin);
                    if (!user.IsManageable)
                        throw new OktaException(OktaRc.USER_NOT_MANAGEABLE, NotManageable(user));

                    if (ctx.StrictVerify)
                    {
                        string status = okta.PrimaryAuthStatus(ctx.TargetLogin, ReadSecret(TargetAccount, false));
                        switch (status.ToUpperInvariant())
                        {
                            case "SUCCESS":
                            case "MFA_REQUIRED":
                            case "MFA_ENROLL":
                            case "PASSWORD_WARN":
                            case "PASSWORD_EXPIRED":
                                break; // password accepted
                            case "LOCKED_OUT":
                                throw new OktaException(OktaRc.USER_NOT_MANAGEABLE, "Okta user " + ctx.TargetLogin + " is LOCKED_OUT. Unlock it in Okta, then verify again.");
                            default:
                                throw new OktaException(OktaRc.GENERAL_ERROR, "Unexpected authentication state '" + status + "' for " + ctx.TargetLogin + ".");
                        }
                    }
                }
                platformOutput.Message = "Okta user " + ctx.TargetLogin + " verified" + (ctx.StrictVerify ? " (password accepted by Okta)." : " (ACTIVE, Okta-sourced).");
                rc = OktaRc.SUCCESS;
            }
            catch (Exception ex) { rc = Fail(ex, ref platformOutput); }
            finally { Logger.MethodEnd(); }
            return rc;
        }

        internal static string NotManageable(OktaUser user)
        {
            return "Okta user " + user.Login + " has status " + user.Status + " and credential provider " + user.CredentialProvider +
                   ". Only ACTIVE Okta-sourced users are managed here (LOCKED_OUT: unlock first; delegated auth: rotate in the source directory).";
        }
    }

    // ----------------------------------------------------------------------------------------------
    // changepass: token with the logon key -> resolve user -> change_password(old, new).
    // ----------------------------------------------------------------------------------------------
    public class Change : BaseAction
    {
        public Change(List<IAccount> accountList, ILogger logger) : base(accountList, logger) { }

        public override CPMAction ActionName { get { return CPMAction.changepass; } }

        public override int run(ref PlatformOutput platformOutput)
        {
            Logger.MethodStart();
            int rc = OktaRc.GENERAL_ERROR;
            try
            {
                OktaContext ctx = BuildContext("Logon");
                string oldPassword = ReadSecret(TargetAccount, false);
                string newPassword = ReadSecret(TargetAccount, true);
                if (string.IsNullOrEmpty(newPassword))
                    throw new OktaException(OktaRc.MISSING_PARAMETER, "CPM did not supply a new password (check ManagementType/password policy on the platform).");

                using (OktaApiClient okta = CreateClient(ctx))
                {
                    string token = okta.GetAccessToken(ctx.ClientId, ctx.PrivateJwk, ctx.Scopes, ctx.AssertionLifetime);
                    OktaUser user = okta.GetUser(token, ctx.TargetLogin);
                    if (!user.IsManageable)
                        throw new OktaException(OktaRc.USER_NOT_MANAGEABLE, Verify.NotManageable(user));
                    okta.ChangePassword(token, user.Id, oldPassword, newPassword, ctx.RevokeSessions);
                }
                platformOutput.Message = "Password changed for " + ctx.TargetLogin + (ctx.RevokeSessions ? " (sessions revoked)." : ".");
                rc = OktaRc.SUCCESS;
            }
            catch (Exception ex) { rc = Fail(ex, ref platformOutput); }
            finally { Logger.MethodEnd(); }
            return rc;
        }
    }

    // ----------------------------------------------------------------------------------------------
    // prereconcilepass: CPM runs this before a Reconcile. Proves the reconcile app key can mint a token.
    // ----------------------------------------------------------------------------------------------
    public class Prereconcile : BaseAction
    {
        public Prereconcile(List<IAccount> accountList, ILogger logger) : base(accountList, logger) { }

        public override CPMAction ActionName { get { return CPMAction.prereconcilepass; } }

        public override int run(ref PlatformOutput platformOutput)
        {
            Logger.MethodStart();
            int rc = OktaRc.GENERAL_ERROR;
            try
            {
                OktaContext ctx = BuildContext("Reconcile");
                using (OktaApiClient okta = CreateClient(ctx))
                {
                    okta.GetAccessToken(ctx.ClientId, ctx.PrivateJwk, ctx.Scopes, ctx.AssertionLifetime);
                }
                rc = OktaRc.SUCCESS;
            }
            catch (Exception ex) { rc = Fail(ex, ref platformOutput); }
            finally { Logger.MethodEnd(); }
            return rc;
        }
    }

    // ----------------------------------------------------------------------------------------------
    // reconcilepass: token with the reconcile key -> resolve user -> admin-set the new password.
    // ----------------------------------------------------------------------------------------------
    public class Reconcile : BaseAction
    {
        public Reconcile(List<IAccount> accountList, ILogger logger) : base(accountList, logger) { }

        public override CPMAction ActionName { get { return CPMAction.reconcilepass; } }

        public override int run(ref PlatformOutput platformOutput)
        {
            Logger.MethodStart();
            int rc = OktaRc.GENERAL_ERROR;
            try
            {
                OktaContext ctx = BuildContext("Reconcile");
                string newPassword = ReadSecret(TargetAccount, true);
                if (string.IsNullOrEmpty(newPassword))
                    throw new OktaException(OktaRc.MISSING_PARAMETER, "CPM did not supply a new password for reconcile.");

                using (OktaApiClient okta = CreateClient(ctx))
                {
                    string token = okta.GetAccessToken(ctx.ClientId, ctx.PrivateJwk, ctx.Scopes, ctx.AssertionLifetime);
                    OktaUser user = okta.GetUser(token, ctx.TargetLogin);
                    if (!user.IsManageable)
                        throw new OktaException(OktaRc.USER_NOT_MANAGEABLE, Verify.NotManageable(user));
                    okta.SetPassword(token, user.Id, newPassword);
                }
                platformOutput.Message = "Password reconciled (admin-set) for " + ctx.TargetLogin + ".";
                rc = OktaRc.SUCCESS;
            }
            catch (Exception ex) { rc = Fail(ex, ref platformOutput); }
            finally { Logger.MethodEnd(); }
            return rc;
        }
    }
}
