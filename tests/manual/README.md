# Manual verification: application-password hardening (v2.8.0)

In-WordPress test scripts for the "Block application passwords for enforced
roles" feature and the XML-RPC password-block fix. Each file is a small,
self-contained snippet designed to run **inside a bootstrapped WordPress** —
via an MCP PHP-execution tool (e.g. Novamira) or `wp eval-file <file>`. They
are intentionally chunked so a small local LLM can execute them one at a time.

These are operator tools, not an automated test suite; they mutate a live
site (temp users, temp role, plugin options) and clean up after themselves.
**Run them on a staging site**, in order:

| # | File | What it asserts |
|---|------|-----------------|
| 1 | `01-preflight.php` | Read-only: plugin ≥ 2.8.0 active, 2FA switch on, filter hooked |
| 2 | `02-setup.php` | Creates throwaway role `gswp_test_role` + 2 temp users + app passwords; snapshots the options it will touch into `gswp_apw_test_state` |
| 3 | `03-phase1-baseline.php` | Block OFF → both users authenticate |
| 4 | `04-phase2-block-on.php` | Block ON → both refused with `application_passwords_disabled_for_user`; the connecting MCP account is unaffected |
| 5 | `05-phase3-exemption.php` | User B exempted → B authenticates, A stays refused |
| 6 | `06-phase4-reversibility.php` | Block OFF → A's original password works again (rejected, not revoked) |
| 7 | `07-cleanup.php` | Restores snapshotted options, deletes temp users/role/state. **Idempotent — safe to run at any point**, including after a mid-run failure |
| 8 | `08-xmlrpc-block.php` | Optional, standalone: enrolled user's password refused over XML-RPC (`gswp_2fa_required`), non-enrolled user unaffected |

Design notes:

- State persists between chunks in the `gswp_apw_test_state` option (variables
  don't survive across separate executions); `02` refuses to run over leftover
  state, and `07` removes it.
- Only the throwaway `gswp_test_role` is ever enforced, so no real account —
  including the application-password account the MCP connection itself uses —
  can be blocked by the run.
- Chunks 3–6 re-apply their own option state, so they can be re-run
  individually after setup.
- Two request-scoped filter shims force `application_password_is_api_request`
  and global app-password availability, so the real core auth path
  (`wp_authenticate_application_password()`) is exercised in-process even on a
  plain-HTTP local site.
- `08` calls the full `wp_authenticate()` stack; if wp-login reCAPTCHA
  protection is enabled with real keys, the missing-token path may interfere
  with its result.

First verified 2026-07-07 against WordPress 6.4.3 (staging): all 13 checks
passed across chunks 1–8.
