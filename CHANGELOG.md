# Changelog

Author: Anilkumar Dadi — Anilkumar.Dadi@cyderes.com — Cyderes

## 1.1 — 2026-09-15
- Token-account platform on the same DLL (`OktaObjectType=ApiToken`): Verify = keep-alive, Change via specify next
  password (validate new token, same-owner check, revoke old), Reconcile refused; codes 8451 / 8452 / 8453.
- `TokenAccountActions.cs`, `platform/Policy-OktaApiTokenAccount.*`, `tools/oktaapitoken-account-test.ini`.

## 1.0 — 2026-09-15
- OktaApiTokenPlugin.dll: .NET SDK CPM plugin for Okta accounts with an Okta API token (SSWS) — logon, verifypass,
  changepass, prereconcilepass, reconcilepass; StrictVerify and session revocation; Okta error → CPM code mapping.
- Platform "Okta Users via API Token - NET plugin" (OktaUsersApiToken), build script, invoker test template.
- Lab evidence: Verify, Change, Reconcile successful from PVWA (18 September 2026).
