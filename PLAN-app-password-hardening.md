# Implementation Plan — Application-Password Hardening for 2FA-Enforced Roles

**Target version:** 2.8.0 (Phase 21)
**Feature:** Close the last password-only authentication path for accounts our 2FA policy is supposed to protect. Role-based enforcement currently guarantees a second factor on every *interactive* login, but REST/application-password logins bypass the challenge **by design** — `GSWP_Two_Factor::enforce_second_factor()` explicitly waves REST requests through (`includes/class-gswp-two-factor.php:279-283`), and WordPress's application-password auth (`wp_authenticate_application_password`) never reaches an interactive challenge anyway. So today a `manage_options` account in an enforced role can still authenticate with a single credential: an application password over the REST API (or XML-RPC). A new opt-in toggle disables application passwords for users in 2FA-enforced roles via the core `wp_is_application_passwords_available_for_user` filter, completing the invariant "enforced accounts cannot authenticate with a password alone." A per-account exemption list keeps deliberate REST integrations (e.g. MCP-server connections) working without weakening anyone else.

**Bug fix bundled in:** the plan/readme have long claimed "we already block XML-RPC" — but `block_non_interactive()` (`includes/class-gswp-two-factor.php:379-392`) has **never been hooked**. It was added in the v2.0.0 rebrand commit and no `add_filter` for it exists anywhere in the codebase or its history, so an enrolled user's real password works over XML-RPC with no second factor today. This phase wires it up, restoring the documented behaviour.

---

## 1. What we already have (reused, not rebuilt)

| Plumbing | Where | Reused for |
| --- | --- | --- |
| Role-enforcement predicate: does this user's role require 2FA? | `GSWP_Two_Factor::role_is_enforced( $user_id )` (`includes/class-gswp-two-factor.php:113-125`) — static, option-driven (`gswp_2fa_enforced_roles`) | The entire policy check for the new filter callback. No new role logic. |
| Feature gate: hooks only register when 2FA is on | Constructor bail on `! self::is_feature_enabled()` (`:64-67`) | The new filter registers in the same constructor, so switching 2FA off site-wide also lifts the app-password block (consistent with the "no one is locked out" master-switch semantics). |
| XML-RPC block for enrolled accounts | `block_non_interactive()` (`:379-392`) — written, documented, **never hooked** | Wired to `authenticate` this phase (bug fix). |
| Core plumbing that honours the filter | WordPress ≥ 5.6 (our floor is 5.8): `wp_is_application_passwords_available_for_user()` gates auth (`wp_authenticate_application_password()` → `application_passwords_disabled_for_user` error), the profile-screen "Application Passwords" section, the `/wp/v2/users/{id}/application-passwords` REST endpoints, and the `authorize_application.php` flow | Returning `false` from one filter closes every application-password surface at once — creation, listing, authorisation, and authentication with already-issued passwords. |
| Settings wiring pattern (option → `gswp_default_options()` → REST get/update → admin localizer → `App.jsx` → panel component) | `google-security-for-wordpress.php:109`, `includes/class-gswp-rest-api.php` (`tfa_remember` at `:94/:217-219` is the exact template), `includes/class-gswp-admin.php:123`, `src/components/TwoFactorNotice.jsx` | The one new setting. |

## 2. Design decisions

1. **Use the per-user filter, not the global one.** `wp_is_application_passwords_available_for_user` receives `( $available, WP_User $user )`, so the block is scoped to exactly the accounts the policy covers. The global `wp_is_application_passwords_available` filter stays untouched: Site Health keeps reporting the feature as available, and users outside enforced roles (shop managers with a fulfilment integration, subscribers, service accounts in a custom un-enforced role) keep full application-password functionality.
2. **Scope = enforced roles, not enrolled users.** The toggle applies to any user whose role is in `gswp_2fa_enforced_roles`, whether or not they have finished enrolling. Two reasons: (a) that is the policy surface — an application password minted *before* enrolment would otherwise survive as a permanent bypass; (b) it matches the toggle's label, so a user who *voluntarily* enrolled in an un-enforced role never has an integration break out from under them. (Parity-with-XML-RPC scoping — "enrolled users" — was considered and rejected for exactly that surprise factor.)
3. **Opt-in, off by default** (`gswp_2fa_block_app_passwords`, default `'0'`), consistent with every behaviour-adding toggle in the plugin — and deliberately upgrade-safe: agency sites commonly connect management tooling (MainWP, WP Umbrella, backup/monitoring services, the WordPress mobile apps) through an administrator application password. Shipping this on-by-default would sever those connections on a routine plugin update for every site that already enforces the Administrator role. The settings UI carries an explicit warning about exactly that (decision 7).
4. **No grace-period interaction.** The enrolment grace window (`grace_deadline()`) exists so a human can keep using the dashboard while they set up an authenticator; it is a UX affordance for interactive work. Application passwords are not part of setting up 2FA, and honouring grace here would leave the bypass open for up to 30 days after the operator explicitly asked to close it. The block applies the moment the toggle is on; the operator chooses when to flip it.
5. **Existing application passwords are rejected, not revoked.** Returning `false` from the filter makes `wp_authenticate_application_password()` refuse authentication (`application_passwords_disabled_for_user`) while the stored passwords remain in user meta. Turning the toggle off instantly restores them — fully reversible, no destructive data change, and no need for a revocation loop over enforced users (which would also have to run on every role/setting change to be complete).
6. **Wire the XML-RPC block at last** (bug fix): `add_filter( 'authenticate', array( $this, 'block_non_interactive' ), 99, 3 )` in the constructor. Priority 99 places it after the password checks (core at 20, reCAPTCHA scoring at 30, Account Defender at 40) and just before `enforce_second_factor` at 100, whose XML-RPC early-return comment (`:276-278`) currently *claims* this hook exists. That block stays scoped to **enrolled** users (its existing behaviour): an enforced-but-unenrolled user can log in interactively with just a password too (enforcement locks the dashboard, not authentication), so blocking their XML-RPC password login would be stricter than the interactive baseline. Note the app-password filter (decision 1) independently covers XML-RPC requests that authenticate *with an application password*, because `wp_authenticate_application_password()` handles `XMLRPC_REQUEST` too — so with the toggle on, enforced accounts have no XML-RPC path either way.
7. **UI placement: inside the existing "Require for roles" section** of the Two-Factor panel — the setting is meaningless without enforced roles, so it lives with the role checkboxes and grace-period input rather than as a top-level toggle. Copy warns about the operational consequence: *"Users in an enforced role can no longer create or sign in with application passwords (REST API / XML-RPC). Existing application passwords for these users stop working immediately — reconnect any site-management or backup tools with a non-enforced account first, or turn this off to restore them."*
8. **Built-in per-user exemption list** (`gswp_2fa_app_password_exempt_users`, default `''`) — a comma-separated list of usernames whose application passwords keep working even though their role is enforced. This is a hard requirement for the agency's own tooling: MCP server connections authenticate with application passwords on admin accounts, and any comparable integration (backup services, the WordPress mobile apps) has the same shape. The exemption is **surgical**: it re-allows application passwords only — the exempted account still gets the full interactive 2FA challenge, the XML-RPC password block, and everything else. Managed centrally in the settings panel (not as scattered per-profile checkboxes) so the whole policy — "block for enforced roles, except these accounts" — is auditable on one screen. Recommended usage documented in the UI copy: point integrations at a dedicated least-privilege service account where possible, and exempt that. The core filter remains a secondary seam for snippet-based overrides (hook `wp_is_application_passwords_available_for_user` later than priority 10).
9. **MainWP note (verify per site, but likely unaffected):** the standard MainWP Dashboard ↔ Child connection authenticates via the MainWP Child plugin's own RSA-key handshake and signs in the configured admin user directly — it does not go through WordPress application passwords, so the toggle should not touch it. Only connections explicitly created as WordPress application passwords (the MCP servers, any REST-based tooling) need the exemption list. The verification checklist includes confirming a MainWP-connected site stays reachable with the toggle on.

## 3. Behaviour matrix

| Authentication path | User in enforced role, toggle **on** | User in enforced role, toggle **off** (default) | User not in enforced role |
| --- | --- | --- | --- |
| Interactive login (wp-login, My Account, AJAX) | 2FA challenge (unchanged) | 2FA challenge (unchanged) | 2FA challenge only if enrolled (unchanged) |
| REST Basic Auth with application password | **Blocked** — `application_passwords_disabled_for_user` (401) | Allowed (the current gap) | Allowed |
| Create/list app passwords (profile UI, REST endpoints, `authorize_application.php`) | **Hidden / rejected** by core | Allowed | Allowed |
| XML-RPC with application password | **Blocked** (same filter, core handles `XMLRPC_REQUEST`) | Allowed | Allowed |
| XML-RPC with real password | Blocked **when enrolled** (bug-fixed `block_non_interactive`) | Blocked when enrolled (bug fix) | Blocked when enrolled (bug fix) |
| WooCommerce REST API keys (consumer key/secret) | Unaffected — separate auth system, not application passwords | Unaffected | Unaffected |
| Cron / programmatic `wp_signon` outside REST/XML-RPC | Unchanged | Unchanged | Unchanged |

**Exemption-list override:** a username on `gswp_2fa_app_password_exempt_users` is treated as "toggle off" for the four application-password rows only — REST Basic Auth, create/list/authorise, and XML-RPC-with-application-password all keep working for that account. Everything else (the interactive 2FA challenge, the enrolled-user XML-RPC password block) applies to exempt accounts exactly as to anyone else.

## 4. Changes by file

### 4.1 `includes/class-gswp-two-factor.php`

- Constructor (inside the existing `is_feature_enabled()` gate, next to the `authenticate` hook at `:74`):
  - `add_filter( 'authenticate', array( $this, 'block_non_interactive' ), 99, 3 );` — the bug fix (decision 6).
  - `add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'restrict_app_passwords' ), 10, 2 );`
- New static predicate mirroring `remember_enabled()` (`:103-105`):

  ```php
  public static function app_password_block_enabled() {
      return self::is_feature_enabled() && '1' === get_option( 'gswp_2fa_block_app_passwords', '0' );
  }
  ```

- New callback:

  ```php
  public function restrict_app_passwords( $available, $user ) {
      if ( ! $available || ! ( $user instanceof WP_User ) || ! self::app_password_block_enabled() ) {
          return $available;
      }
      if ( self::is_app_password_exempt( $user ) ) {
          return $available;
      }
      return ! self::role_is_enforced( $user->ID );
  }
  ```

  Never *grants* availability (only ever narrows an already-true `$available`), so it composes safely with other plugins that disable application passwords — the exemption returns the incoming `$available`, never a hard `true`.
- New static helper `is_app_password_exempt( WP_User $user )`: parses `gswp_2fa_app_password_exempt_users` (comma-separated logins, stored pre-validated by the REST route), lowercases both sides, and matches against `$user->user_login`. A missing/empty option means no exemptions.
- Update the stale comment in `enforce_second_factor()` (`:276-283`): XML-RPC is now genuinely blocked by the hooked `block_non_interactive()`; REST/application-password logins are governed by `restrict_app_passwords()` when the toggle is on, and pass through here otherwise. Cron logins remain untouched.

### 4.2 `google-security-for-wordpress.php`

- `gswp_default_options()`: add `'2fa_block_app_passwords' => '0'` and `'2fa_app_password_exempt_users' => ''` to the Two-factor block (`:146-151`).
- Version → **2.8.0** (header `:5` + `GSWP_VERSION` `:50`).

### 4.3 `includes/class-gswp-rest-api.php`

- `get_settings()`: `'tfa_block_app_passwords'` and `'tfa_app_password_exempt_users'` alongside the other `tfa_*` keys (`:92-95`).
- `update_settings()`: boolean handler for `tfa_block_app_passwords` mirroring `tfa_remember` (`:217-219`). For `tfa_app_password_exempt_users`, mirror the `alert_email` validate-and-rejoin pattern (`:179-188`): split on comma, `sanitize_user()` each entry, keep only logins that resolve via `get_user_by( 'login', … )`, de-duplicate, re-join with `', '` for storage — so a typo'd username is dropped at save time instead of silently never matching.

### 4.4 `includes/class-gswp-admin.php`

- Localizer: add `tfa_block_app_passwords` and `tfa_app_password_exempt_users` next to the existing `tfa_*` entries (`:122-124`).

### 4.5 React UI

- `src/components/TwoFactorNotice.jsx`: inside the `isEnabled`-gated "Require for roles" section (after the grace-period row, before the lock-yourself-out tip), a toggle row styled like the existing "Allow 'Remember this browser'" toggle: **"Block application passwords for enforced roles"**, with the decision-7 warning copy as its description. When that toggle is on, reveal an **"Exempt accounts"** text input beneath it (comma-separated usernames, mirroring the recipients input in `AlertSettings.jsx`), with help text: *"Application passwords keep working for these accounts — use for integrations that must connect via the REST API (e.g. MCP servers). These accounts still get the two-factor challenge on interactive logins. Prefer a dedicated service account over your own login."*
- `src/components/App.jsx`: defaults `tfa_block_app_passwords: '0'` and `tfa_app_password_exempt_users: ''` in the settings state (`:48-50` area); they ride the existing save payload like the other `tfa_*` keys.
- `npm run build`.

### 4.6 Docs & version bump

- `readme.txt`: stable tag, feature bullet ("optionally disable application passwords for 2FA-enforced roles so REST/XML-RPC can't bypass the second factor"), changelog entry for 2.8.0 — including the XML-RPC block fix, and an FAQ note about reconnecting management tools before enabling the toggle.
- `package.json` + `package-lock.json` root → 2.8.0.
- Append the Phase 21 section to `STATE.md`.

## 5. Edge cases & failure modes

- **Agency self-lockout (the big one):** flipping the toggle on immediately kills existing admin application passwords — including any a REST-based integration (MCP servers, backup/monitoring tools) uses to reach the site. Mitigations: off by default (decision 3), explicit warning copy in the UI (decision 7), the built-in exemption list (decision 8) for accounts that must keep REST access, and a non-destructive block (decision 5 — toggle off, or add the account to the exemption list, and everything reconnects with no re-issuing). Standard MainWP Child connections use their own key handshake and should be unaffected (decision 9) — verified in the checklist.
- **Exempt account hygiene:** an exempted admin account is deliberately back to "password-alone REST access" — that's the trade the operator makes for the integration. The UI copy steers toward a dedicated service account; the readme FAQ repeats it. The exemption list is validated at save time (unknown usernames dropped), so it can't silently accumulate dead entries, and renaming a user (rare, DB-level) drops them out of the exemption — fail-closed, the safe direction.
- **2FA master switch off:** the constructor bails, so neither new hook registers — application passwords behave stock. Consistent with the master switch's documented "no one is locked out" semantics, and it means the kill switch for any unforeseen breakage is one toggle away.
- **Filter runs in many contexts** (auth, profile render for the *edited* user on `user-edit.php`, REST endpoints, Site Health): the callback is context-free — pure function of `$user` + options — so every surface agrees. `role_is_enforced()` costs one `get_userdata()` (WP-cached) per call; negligible.
- **Multisite super admins:** `role_is_enforced()` checks `$user->roles`, and a super admin may hold no role on a given subsite — they would not be blocked there. Same existing limitation as role-based 2FA enforcement itself (they're not challenge-enforced either); documented, not solved here.
- **Password-grant fallthrough on REST:** when application-password auth is refused, core does not fall back to treating the credential as a real password for cookie-less REST requests (no other authenticator accepts Basic Auth), so there is no accidental weaker path opened.
- **Users granted an enforced role later / role removed:** the check is live per request (option + current roles), so role changes take effect immediately in both directions with no stored state to reconcile.
- **`authorize_application.php` deep links** (apps requesting a password via the authorisation flow): core shows its own "application passwords are not available for your account" message — acceptable stock messaging, no custom screen needed.
- **XML-RPC fix regression risk:** `block_non_interactive()` only acts when `XMLRPC_REQUEST` is defined *and* the user is enrolled; every other caller passes through untouched. The behaviour matches what the readme/STATE.md have advertised since v2.0.0, so wiring it is a fix, not a behaviour surprise — still called out in the changelog since a site may unknowingly depend on the bypass (e.g. Jetpack-style XML-RPC connections authenticated as an enrolled admin).

## 6. Out of scope (noted for the roadmap)

- Revoking/auditing existing application passwords (a table of who has them, last-used) — WordPress's own profile screen already lists per-user passwords; a cross-user audit is a separate feature.
- Blocking XML-RPC *entirely* for enforced-but-unenrolled users (stricter than the interactive baseline; see decision 6).
- An email alert when a blocked application-password attempt occurs — would ride the Phase 20 `gswp_*` action-hook pattern if wanted later.

## 7. Verification checklist

1. `php -l` on every touched PHP file; `npm run build` + `wp-scripts lint-js` clean.
2. Settings round-trip: toggle on, save, reload → persists; REST `get_settings` returns `tfa_block_app_passwords`.
3. Baseline (toggle off): enforced-role admin creates an application password; `curl -u admin:xxxx…` against `/wp-json/wp/v2/users/me` → 200.
4. Toggle on: same request → 401 with code `application_passwords_disabled_for_user`; profile screen no longer shows the "Application Passwords" section for that user; `POST /wp/v2/users/me/application-passwords` rejected; `authorize_application.php` refuses.
5. Non-enforced user (e.g. editor when only administrator is enforced): application passwords fully functional throughout.
6. Toggle back off: the *original* application password from step 3 works again without re-creation (rejected-not-revoked confirmed).
7. XML-RPC fix: enrolled user, `wp.getUsersBlogs` with their real password → fault with the "XML-RPC login is disabled" message; unenrolled user unaffected. With the toggle on, the same call using an *application* password for an enforced user is also refused.
8. Exemption list: add the step-3 user's login to "Exempt accounts", save → their application password works again while the toggle stays on; a second (non-exempt) enforced admin remains blocked; the exempt user still gets the interactive 2FA challenge on wp-login.php. Save an unknown username → dropped from the stored value on reload.
9. MainWP: with the toggle on (and no exemption), a MainWP-connected staging site remains reachable from the dashboard (sync, updates) — confirming the child-plugin handshake is outside the application-password path. An MCP-server connection on a non-exempt enforced admin fails until that account is exempted.
10. 2FA master switch off → application passwords and XML-RPC behave stock (no filter registered).
11. Site Health → "Application Passwords" availability check still passes (global availability untouched).
