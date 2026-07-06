# Implementation Plan — Account Defender Step 3: Account-Modification Events

**Target version:** 2.6.0 (Phase 19)
**Feature:** Assess and annotate password resets, email changes, and 2FA enable/disable with the same salted `accountId` already sent on login/registration assessments. Completes the Account Defender console checklist and closes the takeover-model gap: today Google only sees the front door (logins), not the actions an attacker takes once inside (rotating the email, disabling 2FA, resetting the password).

---

## 1. What we already have (reused, not rebuilt)

| Plumbing | Where | Reused for |
| --- | --- | --- |
| Salted, opaque `accountId` + `createAccountTime` (`build_account_user_info()`, `resolve_account_id()`, `hash_account()`) | `includes/class-gswp-verifier.php` | Every new assessment. Only change: the context whitelist. |
| Fail-open annotation client (`GSWP_Account_Defender::annotate()`) | `includes/class-gswp-account-defender.php` | Every new annotation. No change needed. |
| Generic token bootstrap that keeps any `.g-recaptcha-response` field populated (pre-fetch, pre-expiry refresh, MutationObserver) | `includes/class-gswp-assets.php` (`enqueue_api_script()` + `add_refresh_bootstrap()`) | Woo "Account details" form and the admin profile form. |
| wp-login.php script printer + per-form submit-time token fetch | `includes/class-gswp-login.php` (`print_scripts()` / `get_inline_js()`) | The reset-password form (`wp-login.php?action=rp`). |
| Feature gating (`GSWP_Account_Defender::is_active()`: Enterprise key + `gswp_account_defender`) | `includes/class-gswp-account-defender.php` | All new hooks bail unless active. |

## 2. Design decisions

1. **Assess where a token is possible; annotate at the terminal outcome.** reCAPTCHA Enterprise cannot create an assessment without a token (standard keys), so every assessed event needs a token field on the form that triggers it. All three target forms are ours to inject into.
2. **Never block, only signal.** These are authenticated users (or users holding a valid reset link). A low score on "change my email" must not lock a legitimate admin out of their own profile. Step 3 assessments are recorded, labeled, logged, and annotated — no `WP_Error` is ever returned from them. (A future step could add a step-up/re-auth policy; out of scope here.)
3. **Deferred outcomes get a pending-assessment store.** Two flows complete in a *later request* that carries no token (the email-change confirmation link, the password-reset email link). The assessment made at request time is stored (user meta / transient) and annotated `LEGITIMATE` when the flow completes. Completion proves control of the account's email — exactly the signal Google wants.
4. **Self-service only.** An admin editing *another* user's profile (email change, 2FA reset) executes with the admin's browser/token; attributing that to the target account would poison the model. Admin-initiated changes are logged (verbose) but never assessed/annotated.
5. **reCAPTCHA action names** (what the frontend `execute()`s with and the assessment's `expectedAction`): `password_reset` (reset form), `account_update` (profile.php and Woo Account details — one form can carry several changes and a token is single-use, so one generic action per form), plus the existing `lostpassword` action gains an accountId.
6. **Gating: one new sub-toggle, default ON.** `gswp_ad_events` (default `'1'`) under the existing Account Defender panel. Enabling Account Defender therefore completes the checklist out of the box, but a site that objects to Google JS on `profile.php`/account pages can switch just the modification events off without losing login coverage. (This mirrors the step-4 philosophy: page-weight trade-offs stay per-site decisions.)
7. **No new score thresholds.** Since nothing blocks, thresholds are meaningless here; the score/labels are logged under verbose logging and the annotation is outcome-based, not score-based.

## 3. Event matrix

| # | Event | Form / token injection | Assessment (action, identifier) | Terminal hook | Annotation |
| --- | --- | --- | --- | --- | --- |
| 1 | Lost-password **request** (already assessed, gains accountId) | existing `lostpassword_form` / Xootix / Woo lost-password (add `woocommerce_lostpassword_form` injection) | `lostpassword`, identifier = requested user (`$user_data` arg of `lostpassword_post`) | email sent (no user-visible outcome) | none at request time; annotated retroactively by #2 (see pending store) |
| 2 | Password reset **completion** | `resetpass_form` (core) + `woocommerce_resetpassword_form`; add `#resetpassform` to the wp-login inline JS selector list | `password_reset`, identifier = `$user` from `validate_password_reset` (POST only — the hook also fires on GET render) | `after_password_reset` | reset-form assessment → `LEGITIMATE`; stored lost-password assessment for the same user (if any) → `LEGITIMATE` |
| 3 | Email change — Woo "Account details" (immediate) | `woocommerce_edit_account_form` | `account_update`, identifier = current user; assess in `woocommerce_save_account_details_errors` only when posted email ≠ current (or password fields are set) | `woocommerce_save_account_details` (same request) | `LEGITIMATE` |
| 4 | Email change — own profile.php (deferred: core sends a confirmation link, `_new_email` meta) | hidden field rendered inside the profile form via `show_user_profile`; api script + refresh bootstrap enqueued on `profile.php` | `account_update`, identifier = current user; assess in `user_profile_update_errors` (self-edits only) when a sensitive change is present | `profile_update` (fires on the confirmation-link request once `user_email` actually changed vs `$old_user_data`) | pending stored assessment → `LEGITIMATE` |
| 5 | Password change while logged in (profile.php `pass1`, Woo account-details password fields) | same forms as #3/#4 | same `account_update` assessment (sensitive-change detector includes password fields) | same request (`profile_update` / `woocommerce_save_account_details`) | `LEGITIMATE` |
| 6 | 2FA **enable** (self-enrolment) | same profile form as #4 (`gswp_2fa_setup_code` posts through it) | same `account_update` assessment | `GSWP_Two_Factor::save_profile()` success branch | `LEGITIMATE` + reason `PASSED_TWO_FACTOR` (a TOTP code was verified) |
| 7 | 2FA **disable** (self, `gswp_2fa_disable`) | same profile form | same `account_update` assessment | `save_profile()` disable branch | `LEGITIMATE` (no reason — the enum has nothing modification-specific; the accountId-bearing assessment itself is the signal) |

Not covered (documented as such): admin-initiated 2FA reset / email change for another user (decision 4); application-password/REST profile changes (no token possible); network-admin email flows.

## 4. Changes by file

### 4.1 `includes/class-gswp-verifier.php`
- Extend the `$account_contexts` whitelist in `build_account_user_info()` with `wp_lostpassword`, `lostpassword` (Woo/Xootix reuse), `password_reset`, `account_update`. Consider extracting the list to a private const for readability.
- No other changes — `verify_token()` already accepts `$account_identifier` and captures `last_assessment_name` / `last_account_assessment`.

### 4.2 `includes/class-gswp-login.php`
- `validate_lostpassword( $errors )` → `validate_lostpassword( $errors, $user_data )` (bump `add_action` arg count to 2; `lostpassword_post` has passed `$user_data` since WP 5.4, within our 5.8 floor). Pass `$user_data` as the identifier. After a successful assessment, hand the assessment name to the pending store (§4.3) keyed to that user, TTL = `apply_filters( 'password_reset_expiration', DAY_IN_SECONDS )`.
- New reset-form support, active when Account Defender events are on **or** the existing `gswp_enable_wp_lostpassword` toggle is on (the reset form is the second half of that flow):
  - `add_action( 'resetpass_form', … )` → inject the hidden field with action `password_reset`.
  - Add `#resetpassform` to the form selector list in `get_inline_js()`.
  - `add_action( 'validate_password_reset', …, 10, 2 )`: bail unless `isset( $_POST['pass1'] )` (hook fires on GET render too); call `verify_token( 'password_reset', 'password_reset', array(), $user )`; never convert a low score into an error (decision 2) — only a genuinely *failed* token (missing/invalid) is ignored too, since availability of the reset flow wins. Record the assessment name in a request static for `after_password_reset`.
- Adjust `is_any_enabled()` / `print_scripts()` gating so scripts also print when only the reset-form path is active.

### 4.3 `includes/class-gswp-account-defender.php`
New "account events" section, all hooks registered in the constructor only when `is_active()` **and** `events_enabled()` (`'1' === get_option( 'gswp_ad_events', '1' )`):

- **Pending-assessment store** (two static helpers): `store_pending( $key, $assessment_name, $ttl )` / `take_pending( $key )` using transients `gswp_ad_pending_{key}` (keys: `lostpw_{user_id}`, `email_{user_id}`). Small, self-expiring, no schema.
- **`after_password_reset` (10, 2 args)**: annotate this request's reset-form assessment (from `GSWP_Login`, exposed via a setter or a shared request static) `LEGITIMATE`; also `take_pending( 'lostpw_{ID}' )` and annotate it `LEGITIMATE`. Log under verbose.
- **Profile form assessment**: hook `user_profile_update_errors` (3 args). Bail unless it's a self-edit (`$user->ID === get_current_user_id()`), a token was posted, and a *sensitive change* is present: posted `email` ≠ current email, `pass1` non-empty, `gswp_2fa_setup_code` posted, or `gswp_2fa_disable` posted. Call `verify_token( 'account_update', 'account_update', array(), get_current_user_id() )`; stash the assessment name + which sensitive changes were seen in request statics. If the email is changing, also `store_pending( 'email_{ID}', $name, WEEK_IN_SECONDS )` (core's `_new_email` confirmation has no hard expiry; a week bounds staleness).
- **`profile_update` (2 args, `$user_id, $old_user_data`)**: if `user_email` changed — immediate change (admin contexts we skip; Woo path arrives here too) or the confirmation-link request — `take_pending( 'email_{ID}' )` and annotate `LEGITIMATE`; else if this request's static assessment exists and a password change was among the detected changes, annotate it `LEGITIMATE` once (guard with the existing `$annotated`-style static so one request never double-annotates one assessment).
- **Woo Account details**: `woocommerce_edit_account_form` → inject hidden field (action `account_update`) + `GSWP_Assets::enqueue_api_script()` + `add_refresh_bootstrap()`; `woocommerce_save_account_details_errors` (2 args) → same sensitive-change detector + assessment; `woocommerce_save_account_details` → annotate `LEGITIMATE` (immediate email/password changes; Woo has no confirmation step).
- **Profile page assets**: on `admin_enqueue_scripts` for `profile.php` only (not `user-edit.php` — decision 4), enqueue the api script + refresh bootstrap; render the hidden field inside the profile `<form>` via `show_user_profile` (priority 1 so it sits above our 2FA section). Verify `GSWP_Assets` enqueues cleanly in admin context (it uses the standard `wp_enqueue_script` registry, so it should; flag for testing).
- **Accessor for the 2FA class**: `public static function current_modification_assessment()` returning this request's `account_update` assessment name, plus a static `consume_modification_annotation()`-style guard so §4.4 and the `profile_update` hook don't both annotate.

### 4.4 `includes/class-gswp-two-factor.php`
- In `save_profile()`:
  - Successful first-time enrolment branch → `GSWP_Account_Defender::annotate( name, 'LEGITIMATE', array( 'PASSED_TWO_FACTOR' ) )` using `current_modification_assessment()` (guarded by the same `class_exists`/`is_active()` pattern as `annotate_2fa()`).
  - Self-disable branch (`gswp_2fa_disable`) → annotate `LEGITIMATE`, no reasons; log "2FA disabled for account …" under verbose so a takeover investigation has a trail even when annotation is off/failed.
  - Admin-disable branch: verbose log only, no annotation (decision 4).
- No changes to the login-challenge/annotation code paths from Phase 13.

### 4.5 Settings wiring (`gswp_ad_events`, default `'1'`)
- `gswp_default_options()` in `google-security-for-wordpress.php`: `'ad_events' => '1'`.
- `includes/class-gswp-rest-api.php`: add `ad_events` to the `get_settings` payload and to the boolean-toggle list in `update_settings`.
- `includes/class-gswp-admin.php` localizer: pass through with the other AD settings.
- `src/components/AccountDefender.jsx`: third row (shown when the master toggle is on, same pattern as the step-up toggle): "Assess account changes" — copy explaining it covers password resets, email changes, and 2FA changes, and that it loads the reCAPTCHA script on the profile/account pages. Update the panel intro paragraph to mention account-modification coverage.
- `src/components/App.jsx`: add the default to initial state if defaults are enumerated there.

### 4.6 Version bump + docs
- 2.6.0 in the main header, `GSWP_VERSION`, `readme.txt` (stable tag, feature bullet, changelog), `package.json`, `package-lock.json` root.
- New Phase 19 section in `STATE.md` describing the shipped behavior (same style as prior phases).
- `npm run build` (React panel changed).

## 5. Edge cases and risks

- **`validate_password_reset` fires on GET** (form render): the `pass1` guard is mandatory or we'd burn an assessment (and a missing-token log) per render.
- **Single-use tokens**: one form POST = one token = one assessment. That's why profile.php gets one `account_update` assessment per save, not one per change type; the terminal hooks decide which annotations attach to it (only ever one annotate call per assessment — the API treats annotate as latest-wins, so pick one: the guard in §4.3 enforces first-outcome-wins, with 2FA enrolment taking precedence since it carries a reason).
- **Woo lost-password/reset hook parity**: WooCommerce's `WC_Form_Handler::process_lost_password()` funnels through core `retrieve_password()` (fires `lostpassword_post`) and its reset flow calls core `reset_password()` (fires `after_password_reset`) — verify both on the current Woo version during testing; if the reset path proves not to fire the core hook, add `woocommerce_customer_reset_password` as a fallback terminal hook.
- **Page caches on wp-login.php reset form**: the existing submit-time token fetch pattern (`get_inline_js()`) already handles stale pages; no new work, but include in the test matrix (FlyingPress site).
- **profile.php weight**: the enterprise script now loads on the profile screen when AD events are on. It's admin-only, feature-gated, and toggleable (`gswp_ad_events`) — acceptable, but call it out in the changelog/panel copy.
- **`_new_email` cancellation**: if the user dismisses the pending email change, the pending transient just expires after a week un-annotated. Correct behavior (the change never happened), no cleanup hook needed — though `delete_user_meta` on core's `dismiss` action could be added if we want tidiness.
- **Annotation with no prior assessment**: every annotate call is already guarded (`'' === $name` bail in `annotate()`), so flows where reCAPTCHA never loaded (script blocked, classic key, events off) degrade to silence, never errors.

## 6. Verification checklist (manual, staging with an Enterprise key)

1. Login/registration regression: existing annotations (`CORRECT_PASSWORD`, `INCORRECT_PASSWORD`, 2FA trio) still fire once each; no double annotation.
2. Lost password from wp-login.php and Woo My Account → assessment created with `userInfo.accountId` (verbose log), pending transient set.
3. Complete the reset from the email link → both assessments annotated `LEGITIMATE` (check GCP logs / verbose log lines).
4. profile.php: change email → assessment at save, annotation only after clicking the confirmation link; change password → assessed + annotated same request; enable 2FA → `LEGITIMATE` + `PASSED_TWO_FACTOR`; disable 2FA → `LEGITIMATE`.
5. Woo Account details: email and password changes assessed + annotated in one request.
6. Admin edits another user (email change, 2FA reset) → no assessment, no annotation, verbose log only.
7. Toggle `gswp_ad_events` off → no reCAPTCHA script on profile.php/account pages, login coverage unaffected.
8. Classic key / AD off → all new hooks inert (constructor bails).
9. `php -l` on touched files, `npx wp-scripts lint-js`, `npm run build`, packaged zip sanity-load on a clean install.
10. GCP console: Account Defender checklist shows account-modification events flowing; labels begin appearing after the model warms up.

## 7. Out of scope (noted for the roadmap)

- **Step 4 — site-wide passive telemetry script** (loading reCAPTCHA on every front-end page for continuous behavioral signal): to be implemented as its own opt-in toggle, default off, decided per client — it trades page weight for signal and is orthogonal to this change.
- Blocking/step-up policies on suspicious account modifications (e.g. require re-auth before an email change when `SUSPICIOUS_ACTIVITY` labels appear). Worth revisiting once step-3 data accumulates.
- Assessing admin-initiated changes to other users' accounts.
