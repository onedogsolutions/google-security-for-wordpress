# Implementation Plan — Bind 2FA enrolment to its origin site (stop TOTP secrets transferring to cloned/staging copies)

## Status: PROPOSED — not yet implemented. Awaiting approval before writing code.

## 1. The reported problem

- Parent site: `https://maddogproducts.com/`
- Staging clone: `https://staging.maddogproducts.com/`
- 2FA (Google Authenticator) was enrolled on the parent **before** the clone was
  made. The **same** Authenticator code logs the user into the staging site.

## 2. Root cause (and what it is *not*)

A TOTP code is a pure function of a **shared secret** + the **current time** —
nothing else. This plugin stores that secret in user meta
(`GSWP_Two_Factor::META_SECRET` = `gswp_2fa_secret`) and verifies a submitted
code against it in `verify_user_code()`. The code carries **no domain binding**;
Google Authenticator simply computes `TOTP(secret, now)`.

Cloning the site copies the entire `wp_usermeta` table verbatim, so the staging
database holds the **identical** secret the authenticator was provisioned
against. Identical secret → identical code → it works on both hosts. The
`otpauth://` label (`issuer:user_login`, from `render_setup_rows()`) is copied
too, so both sites appear under the same entry in the app.

**This is inherent TOTP behaviour, not a plugin bug per se — but it is a
security-hygiene gap the plugin should close.**

### reCAPTCHA is unrelated (explicitly)

reCAPTCHA / Account Defender score bot-likelihood using site keys registered to
domains — a separate subsystem from TOTP. Whether the reCAPTCHA key covers one
domain or both has **zero** effect on whether a TOTP code works on the clone.
Restricting the key to one domain would not stop the code; covering both domains
does not "authorise" a shared second factor. The two systems must not be
conflated.

## 3. Why it is worth fixing (severity) — and the honest caveat

**Risk — cross-environment TOTP replay.** A code is valid for its time-step
(~30–90s with the ±1 step window) on *any* site sharing the secret, and this
plugin's replay guard (`META_LAST_TS`) is **per-database** — a code burned on
staging is not burned on production. So a code entered/observed on a lower-trust
staging box (often shared with contractors, sometimes plain HTTP, debug on) can
be replayed against production within the window. Combined with a known / reused
/ phished password, that is a 2FA bypass on the live site.

**Caveat — the plugin cannot fully solve clone secret leakage.** A full clone
already copies the password *hashes* and the *raw* TOTP secrets. Anyone with
staging DB/file access can generate valid production codes regardless of plugin
logic; that is a provisioning problem for whoever creates the clone (scrub
secrets, or set `WP_ENVIRONMENT_TYPE=staging`). What the plugin *can* do — and
what this plan does — is stop **the cloned site itself** from silently honouring
the production authenticator. This is defense-in-depth, not a complete fix, and
the plugin copy/FAQ should say so.

## 4. Design — origin-host binding

Record the site the secret was enrolled on; refuse to honour a secret whose
recorded origin does not match the current site.

### 4.1 What we record

- New user meta constant `META_ORIGIN = 'gswp_2fa_origin'`, storing the
  **normalized host** of `home_url()` at enrolment time.
- Normalization (a new private static `current_site_origin()` helper):
  - `wp_parse_url( home_url(), PHP_URL_HOST )`
  - `strtolower()`
  - strip a leading `www.`
  - host only — **ignore scheme and port** (so an http→https switch or a
    `:8080` dev port never trips it).
- Store host in plaintext (not sensitive; aids admin display/debugging).

### 4.2 The mismatch predicate

New private helper `secret_is_foreign( $user_id )`:
- If env-binding is disabled (see 4.5) → always `false`.
- Read `META_ORIGIN`. If **empty/missing** → `false` (grandfather in; see 4.4).
- Return `true` when the stored origin !== `current_site_origin()`.

### 4.3 Integration — one choke point, `user_has_2fa()`

`user_has_2fa()` is the single predicate every path already consults
(`enforce_second_factor`, `block_non_interactive`, `restrict_app_passwords`,
`maybe_enforce_setup`, the profile UI, `ajax_verify`). Make it return **false**
when `secret_is_foreign()` is true:

```php
public static function user_has_2fa( $user_id ) {
    if ( ! self::is_feature_enabled() ) {
        return false;
    }
    if ( '1' !== get_user_meta( $user_id, self::META_ENABLED, true )
        || '' === (string) get_user_meta( $user_id, self::META_SECRET, true ) ) {
        return false;
    }
    if ( self::secret_is_foreign( $user_id ) ) {
        return false; // Secret belongs to a different site (clone/migration).
    }
    return true;
}
```

Consequences, all desirable:
- **`enforce_second_factor()`** returns `$user` unchanged → the cloned code
  stops working and login proceeds on password alone. This is the **fail-open**
  choice: a secret that no longer belongs here must never *block* login (that
  would lock every admin out of a legitimately migrated site).
- **`ajax_verify()`** short-circuits to "session expired, sign in again" (it
  already re-checks `user_has_2fa`).
- **`maybe_enforce_setup()`** (enforced roles) now sees the user as
  *unenrolled* → routes them through **fresh re-enrolment** on the new host
  (grace handling in 4.6). This is the graceful path for a legit production
  migration: 2FA is re-established rather than silently dropped.
- **`restrict_app_passwords()`** — no adverse change.
- **Profile screen** renders the first-time setup rows again, so re-enrolment
  mints a **new** secret and stamps the **new** origin.

### 4.4 Backfill for existing enrolments (upgrade migration)

Existing users have no `META_ORIGIN`, so `secret_is_foreign()` grandfathers them
(returns false) until stamped. Add a one-time backfill in the existing
`gswp_db_version`-gated `gswp_maybe_migrate()` path (or a dedicated
version-gated routine it calls): for every user with `META_ENABLED === '1'` and
no `META_ORIGIN`, set `META_ORIGIN = current_site_origin()`.

- Run it guarded so it executes once per version bump.
- **Documented limitation:** the backfill stamps whichever host runs the upgrade
  first. On a normal production upgrade this is correct, and **future** clones
  (made after the upgrade) are then caught because they carry origin=production
  while running on the staging host. It **cannot** retroactively distinguish an
  *already-existing* clone — if the upgrade happens to run on that clone first,
  the clone stamps itself as its own origin. This is acceptable: the reported
  staging site should be remediated manually once (admin resets 2FA on staging,
  or user re-enrols there), and all *new* clones going forward are covered.

### 4.5 Admin control

- New option `gswp_2fa_env_binding`, **default `'1'`** (on), added to
  `gswp_default_options()`.
- New static `env_binding_enabled()` = `is_feature_enabled() && '1' === get_option( 'gswp_2fa_env_binding', '1' )`, consulted by `secret_is_foreign()`.
- Also expose a filter `gswp_2fa_site_origin` around `current_site_origin()` so
  advanced setups (multisite domain mapping, reverse-proxy host rewriting) can
  override the identity used.
- Wire through REST `get_settings`/`update_settings` (boolean toggle,
  mirroring `tfa_remember`), the admin localizer, `App.jsx` defaults, and a new
  toggle row in `src/components/TwoFactorNotice.jsx`
  ("Disable 2FA on cloned/moved sites"), with copy explaining the staging use
  case and that it re-requires enrolment after a domain change.

### 4.6 Grace-clock reset on a detected move (avoid instant lockout)

`META_GRACE_START` is copied by the clone too, so an already-expired deadline
would instantly hard-redirect an enforced user on the new host. When
`maybe_enforce_setup()` observes an enforced user whose secret is foreign, clear
`META_GRACE_START` **once** for that user so `grace_deadline()` starts a fresh
window on the new host instead of locking immediately. (Enrolment already clears
it via `save_profile()` / `disable_for_user()`.)

Guard the reset so it fires only when a foreign secret is actually present (a
stored origin exists and differs), not for genuinely new unenrolled users.

### 4.7 Optional messaging via `wp_get_environment_type()`

Not required for enforcement, but improves the notice: when the current host
differs from the stored origin **and** `wp_get_environment_type()` is
`staging`/`development`/`local`, the admin notice can say "This looks like a
staging copy of another site; two-factor authentication has been reset for this
environment." On `production` it can say "This site's address changed; please
re-enrol in two-factor authentication." Pure copy — no behavioural change.

## 5. Edge cases / false-positive control

- **www vs non-www, http vs https, port** — neutralised by normalization (host
  only, `www.` stripped, scheme/port ignored).
- **Legitimate production domain change** — never hard-locks (fail-open in
  `enforce_second_factor`); enforced users are re-enrolled with a fresh grace
  window; unenforced users keep working on password until they re-enrol. An
  admin notice prompts re-enrolment for everyone.
- **Trusted-device cookies** — already domain-scoped via `COOKIE_DOMAIN`, so a
  production trust cookie is never sent to the staging host; no change needed.
- **Backup codes** — only consulted inside a challenge, which no longer fires
  for a foreign secret, so cloned backup codes are inert too. Correct.
- **Multisite** — users are network-level but `home_url()` is per-site;
  subdomain/domain-mapped multisite could see spurious mismatches. **Out of
  scope for v1**; the `gswp_2fa_site_origin` filter is the escape hatch, and the
  behaviour is gated behind the default-on toggle operators can disable.
- **REST/XML-RPC/cron** — unaffected: those paths already bypass the interactive
  challenge, and `restrict_app_passwords()` keying off `user_has_2fa()` simply
  stops treating a foreign-secret user as enrolled (app-password block lifts for
  them on the clone, which is fine — the clone is not the account's real home).

## 6. Files to change

- `includes/class-gswp-two-factor.php`
  - Add `META_ORIGIN` const.
  - Add `current_site_origin()`, `env_binding_enabled()`, `secret_is_foreign()`.
  - Gate `user_has_2fa()` on `secret_is_foreign()`.
  - Stamp `META_ORIGIN` on successful enrolment in `save_profile()` (next to the
    existing `META_SECRET`/`META_ENABLED` writes).
  - Clear stamp in `disable_for_user()` (add `delete_user_meta( …, META_ORIGIN )`).
  - Grace-clock reset in `maybe_enforce_setup()` on a detected move (4.6).
  - Optional env-type messaging in `render_grace_notice()` / a new notice (4.7).
- `google-security-for-wordpress.php`
  - Add `'2fa_env_binding' => '1'` to `gswp_default_options()`.
  - Add the version-gated backfill (4.4) in/near `gswp_maybe_migrate()`.
  - Version bump (see §8).
- `includes/class-gswp-rest-api.php`
  - Add `tfa_env_binding` to `get_settings` and `update_settings`.
- `src/components/TwoFactorNotice.jsx` + `src/components/App.jsx`
  - New toggle + default.
- `readme.txt` — feature bullet, a "Why did 2FA reset after I cloned my site?"
  FAQ, changelog, stable tag.
- `STATE.md` — new phase entry.

## 7. Verification checklist (staging)

1. **Baseline** — enrol on the origin host; code works; `gswp_2fa_origin` == its
   normalized host.
2. **Clone** — copy DB to a second host; enrolled user's production code is
   **rejected**; login proceeds on password only (unenforced) or is routed to
   re-enrolment (enforced) with a **fresh** grace window (no instant lockout).
3. **Re-enrol on clone** — new secret minted, new origin stamped, the two sites'
   authenticator entries are now independent (disabling on one does not affect
   the other).
4. **Legit migration** — change `home_url()` host on the *same* DB; confirm no
   hard lockout, admins can still log in, enforced users get the re-enrol notice.
5. **False-positive guard** — flip www/non-www, http/https, add a port; confirm
   **no** mismatch is triggered.
6. **Toggle off** — `gswp_2fa_env_binding = 0` restores the old portable
   behaviour (secret works across hosts).
7. **Backfill** — a pre-upgrade enrolled user with no origin is stamped once on
   upgrade and behaves as (1).
8. `php -l` clean on all touched PHP; `wp-scripts lint-js` clean on the JSX;
   `npm run build` for the React changes.

## 8. Version / packaging

- New user-facing option ⇒ **minor** bump to **2.10.0** across: main header,
  `GSWP_VERSION`, `readme.txt` stable tag + changelog, `package.json`,
  `package-lock.json` root.
- React rebuild required (JSX toggle added).
- New class? No — all PHP changes are inside existing files, so the distribution
  ZIP file list is unchanged.

## 9. Out of scope / follow-ups

- Automatic secret scrubbing at clone time (host/provisioning responsibility).
- Multisite-aware origin identity (filter provided as the escape hatch).
- Binding password hashes / other secrets to origin (this plan covers 2FA only;
  the same class of clone-leak applies to any stored secret and is ultimately a
  clone-hygiene concern).
