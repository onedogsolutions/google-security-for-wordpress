# Investigation & Implementation Plan — Account Defender "Configure" Recommendation + Continued Spam Registrations

**Target version:** 2.12.0 (Phase 27)
**Reported (onedog.solutions, morning after installing 2.11.0):** two more spam registrations overnight (same signature: gibberish First/Last/Website, Gmail dot-trick address `d.el.ontea.nth.ony@gmail.com`), and the Google Cloud **Fraud Defense** console still shows the "Explore Account defense features → **Configure Account defense**" recommendation ("Applies to 3 keys", "1% of your assessments are account related"), despite the plugin having coded the four documented Account Defender pieces (provide account ID, annotate events, report actions, provide data).

**Doc-verification caveat:** this environment's network policy blocks `docs.cloud.google.com` (proxy CONNECT 403), so the Google-docs statements below are from prior knowledge of the Account Defender guide, not a fresh fetch. Nothing in the plan depends on a doc detail that isn't also verifiable directly in the Cloud console; the operator checklist (§3) confirms each one there.

---

## 1. Finding 0 — the console recommendation is an operator step the plugin cannot perform

The four doc anchors the plugin implemented are the **API-side integration**. Turning Account Defender on is a **separate, console-side activation**: in the new Fraud Defense UI it is the per-key "Account defense" feature (exactly the blue **Configure Account defense** button in the screenshot, "Applies to 3 keys"); in the older reCAPTCHA UI it was Settings → Account defender → Enable. The plugin's API key can create assessments and annotations, but it does not (and should not) mutate key/feature configuration — so no amount of plugin code clears that recommendation.

Until the feature is enabled on the keys:

- assessments return **no `accountDefenderAssessment` labels**, so everything label-driven in the plugin is dormant: the 2FA step-up (`gswp_ad_step_up`), the suspicious-admin-login alert (Phase 20), and any `SUSPICIOUS_ACCOUNT_CREATION` signal on registrations;
- Google's site-specific model isn't training on the accountIds/annotations we do send.

The "1% of your assessments are account related" figure is Google's own classification of recent traffic. It is consistent with the settings-side suspicion in §2.6 (Account Defender toggle off → no `userInfo.accountId` attached at all) and/or with checkout/other assessments dominating the volume across the 3 keys. After enabling, the recommendation card may also simply persist until Google has seen enough account-tagged assessments — it is a rolling recommendation, not a binary "configured" flag.

**Action: operator clicks Configure Account defense for the relevant key(s). No release required.** (§3.1.)

## 2. Why spam still registered — six code/config findings

The Phase 26 integration itself is working as designed (the hook points, injection, and blocking shape were source-verified against PowerPack 2.42.3, and `pp_rf_before_user_register` halts `wp_insert_user()` on a failed check). The two overnight registrations therefore got through one of these:

### 2.1 The protection blocks on *score only*; Account Defender labels are never read at registration time

`GSWP_Powerpack::validate_registration()` → `verify_token( 'wp_register', 'register', …, $email )` rejects a missing/invalid token or a score below `gswp_threshold_wp_register` (**default 0.5**). Modern spam runs real-browser automation or human farms that routinely score 0.5–0.9, so a valid, passing token is entirely plausible — and then nothing else stands in the way:

- `GSWP_Verifier::get_last_account_labels()` is consulted **only** in `GSWP_Account_Defender::capture_login_assessment()` (the `authenticate` filter, i.e. logins). On a registration, a returned `SUSPICIOUS_ACCOUNT_CREATION` label is not read, not logged, not blocked on, and not alerted on. The exact label Google built for this attack is dropped on the floor.

### 2.2 Registrations are never annotated — the fake-signup feedback loop (checklist item "annotate events") is incomplete

Login outcomes are annotated (`wp_login` → `LEGITIMATE + CORRECT_PASSWORD`, `wp_login_failed` → `INCORRECT_PASSWORD`), 2FA outcomes are annotated, Phase 19 annotates account-modification events. **No registration outcome is ever annotated**: there is no `user_register` hook anywhere in the plugin, the registration assessment name is discarded at the end of the request, and when the operator deletes the spam accounts, Google is never told they were `FRAUDULENT`. Account Defender's fake-signup model is site-specific and learns from annotations — right now it gets zero supervised signal on the one event type under attack. This is the biggest genuine gap against the four doc anchors.

### 2.3 The Gmail dot-trick defeats the hashed accountId (checklist items "provide account ID" / "provide data" are weakened)

`GSWP_Verifier::resolve_account_id()` keys a registration by `hash( salt + 'email:' . strtolower( $email ) )` — dots and `+tags` retained. Every dot-variant (`d.el.ontea.nth.ony@` vs `del.onteanthony@` …) therefore hashes to a **different accountId**, so from Google's side each spam signup is a brand-new, unrelated account: `RELATED_ACCOUNTS_NUMBER_HIGH` clustering and repeat-signup detection are blinded to precisely the observed attack. Because we send only the salted hash (by design, for privacy), Google cannot normalize the email itself — the docs recommend also sending `userInfo.userIds` (email/phone/username) for this reason, which the plugin deliberately never does.

### 2.4 Auto-login after registration can annotate a spam signup as LEGITIMATE

`capture_login_assessment()` captures `verifier->get_last_assessment_name()` **whatever context created it**. If a registration form auto-logs the new user in via `wp_signon()` in the same request (a PowerPack RF module option; Xootix does the equivalent), `authenticate` fires after `validate_registration()`, captures the *registration* assessment, and `wp_login` then annotates it `LEGITIMATE + CORRECT_PASSWORD`. A spam signup that passed the score would be actively taught to Google as legitimate. (Whether the module's auto-login setting is on for onedog.solutions needs checking, but the code path is wrong regardless.)

### 2.5 Fail-open failures are invisible on non-WooCommerce sites

Every fail-open branch in `GSWP_Verifier` (unconfigured keys, HTTP non-200 from the assessments API — e.g. an API key with referer restrictions that reject server-side calls) logs via `wc_get_logger()` **only**; without WooCommerce, `GSWP_Verifier::log()` is a silent no-op (unlike `GSWP_Account_Defender::static_log()`, which falls back to `error_log` under WP_DEBUG). If onedog.solutions doesn't run WooCommerce and the Enterprise call is failing, verification is being skipped with no trace.

### 2.6 Settings on the site must be re-verified (cannot be confirmed from the repo)

All of the new code is inert unless the operator flipped the right switches after updating:

- **Form Protection → WordPress registration** (`gswp_enable_wp_register`) must be ON — this is the toggle Phase 26 reuses (called out in PLAN-spam-registration-blocking.md §6 as a deployment note).
- **Key type = Enterprise** with project ID + API key + site key all present (otherwise `verify_token()` returns `true` unconditionally).
- **Enterprise Defense → Account Defender** (`gswp_account_defender`, default **0**) must be ON, or no `userInfo.accountId` is attached to any assessment — which alone would explain the console's "1% account related".

## 3. Operator checklist (do now — no release needed)

1. **Google Cloud console → Fraud Defense:** click **Configure Account defense** and enable it for the key(s) serving these sites. Confirm afterwards under the key's settings that Account defense shows enabled.
2. **Plugin settings on onedog.solutions:** confirm key type Enterprise + credentials, **WordPress registration** toggle ON, **Account Defender** ON, and temporarily enable **verbose logging**.
3. **Console → Fraud Defense → Attacks/assessment metrics:** find the two overnight registrations' assessments (action `register`, overnight window). Their existence + score answers which of §2.1/§2.5/§2.6 let them through: no assessments → the toggle/config path (§2.5/§2.6); assessments with passing scores → §2.1.
4. **Raise `threshold_wp_register` to 0.7** (Form Protection tab). Registration is a low-friction surface — a false positive just means a retry — so it tolerates a stricter threshold than login.
5. Delete the spam accounts (after the §4 code ships, such deletions will feed `FRAUDULENT` annotations automatically; deleting them now is still right, it just pre-dates the feedback loop).
6. If open registration isn't actually needed on this site, also unpublish the form / disable "Anyone can register" (repeat of the Phase 26 deployment note).

## 4. Implementation plan (Phase 27, v2.12.0)

### 4.1 `GSWP_Verifier` — expose the assessment context, normalize Gmail identifiers

- New private `$last_context` set at the top of `verify_token()`; public getter `get_last_context()`. (Enables §4.2's capture guard and §4.3's `user_register` pickup.)
- New private `normalize_email_identifier( $email )` used by `resolve_account_id()` before hashing: lowercase; for `gmail.com` / `googlemail.com` strip dots from the local part, strip a `+suffix`, and fold `googlemail.com` → `gmail.com`. All dot-variants of one inbox then map to **one stable accountId**, restoring related-account clustering against exactly the observed attack. (Non-Gmail domains: lowercase only — dot/plus semantics aren't safe to assume elsewhere.)
- `log()`: add the same `error_log`-under-`WP_DEBUG` fallback `GSWP_Account_Defender::static_log()` already has, so fail-open events are visible on non-Woo sites (§2.5).
- **Optional, default-off** `gswp_ad_share_email` toggle: when ON, registration/login assessments also carry `userInfo.userIds = [ { email } ]` per the docs' recommendation (markedly better detection; lets Google do its own normalization). Off by default to preserve the current privacy posture; the settings UI copy must state plainly that raw emails are sent to Google when enabled.

### 4.2 `GSWP_Account_Defender` — scope the login capture (fix §2.4)

`capture_login_assessment()` returns early unless `verifier->get_last_context()` is a login context (`login`, `wp_login`). An auto-login riding a registration request then no longer captures — and `wp_login` no longer mis-annotates — the registration assessment.

### 4.3 `GSWP_Account_Defender` — registration outcome feedback loop (fix §2.2)

New "registration events" section, active under `is_active()` (no new toggle — this is the missing half of the existing Account Defender feature):

- **`user_register` (priority 10):** if `get_last_context()` is a registration context (`registration`, `wp_register`) and an assessment name exists, store it in user meta `gswp_registration_assessment` with a timestamp. `user_register` fires inside `wp_insert_user()` for every covered surface (PowerPack RF, core, WooCommerce, Xootix), so one hook covers all four; an admin-created user has no assessment in-flight → meta simply isn't written.
- **First real login = legitimate signup:** in `on_login_success()`, after the existing login annotation, consume `gswp_registration_assessment` if present → `annotate( $name, 'LEGITIMATE' )`, delete the meta. (One extra annotate call, once per account, only for accounts registered under Account Defender.)
- **Deletion before first login = fraudulent signup:** hook `delete_user`; if the target still carries `gswp_registration_assessment` (i.e. never completed a login), `annotate( $name, 'FRAUDULENT' )`. The meta-still-present guard keeps ordinary staff-offboarding deletions of long-standing accounts from ever mis-annotating. Assessment names remain annotatable well past the initial token window, so a morning cleanup of overnight spam feeds the model correctly.

### 4.4 Registration-time label handling + alert (fix §2.1)

- New `GSWP_Account_Defender::screen_registration( $context )` static helper (or instance method reached via the shared instance): reads `get_last_account_labels()` after a **passing** `verify_token()` in each registration validator (`GSWP_Powerpack::validate_registration()`, `GSWP_Login::validate_register()`, `GSWP_Verifier::validate_registration()` (Woo), `GSWP_Xootix` registration), and:
  - logs any labels (verbose: all; default: risk labels only — mirroring the login capture);
  - when new toggle **`gswp_ad_block_signup`** (default `0`) is ON and `SUSPICIOUS_ACCOUNT_CREATION` is present → return a `WP_Error` the caller surfaces exactly like a low score (PowerPack: `wp_send_json_error` with the module's error shape; core/Woo/Xootix: add to the errors object). Opt-in because the label only starts flowing once the console feature is enabled and trained (§1) — shipping it default-on would block nobody today and risk false positives later with no operator awareness.
  - fires **`do_action( 'gswp_suspicious_registration', $email, $labels, $context_array )`** independent of the block toggle — the Phase 20 alerts seam. `GSWP_Alerts` gains a third subscriber + per-event sub-toggle (`gswp_alert_registration`, default `1`), dedupe key `registration_{md5(normalized email)}`, riding the existing throttle/digest pipeline unchanged. Phase 20 explicitly listed `SUSPICIOUS_ACCOUNT_CREATION` alerts as roadmap; this closes it.

### 4.5 Settings wiring

New options `gswp_ad_block_signup` (`'0'`), `gswp_ad_share_email` (`'0'`), `gswp_alert_registration` (`'1'`) through the standard chain: `gswp_default_options()`, REST `get_settings`/`update_settings` (plain toggles), admin localizer, `App.jsx` defaults, `AccountDefender.jsx` (two new rows: "Block suspicious sign-ups", "Send email identifiers to Google" with the privacy caveat), `AlertSettings.jsx` (third event sub-toggle). MainWP bridge picks all three up automatically (single-source validation through the REST route). React rebuild required.

### 4.6 Docs & version

- `readme.txt`: stable tag 2.12.0; changelog covering the registration feedback loop, Gmail normalization, signup blocking/alert toggles, the login-capture scoping fix, and the logging fallback; new FAQ **"Why does Google Cloud still ask me to configure Account Defense?"** (the §1 explanation — console-side enablement is a Google Cloud step the plugin cannot perform, plus the settings checklist from §3).
- Version bump in the usual five places; STATE.md Phase 27 section on completion.

### 4.7 Edge cases

- **Gmail normalization vs existing accountIds:** a previously-registered gmail user's hash changes (dots/plus now stripped). Acceptable: Account Defender tolerates identifier changes (it re-learns), the hash is already salted per-site, and the console feature is only now being enabled — there is no trained history to lose. Called out in the changelog.
- **`delete_user` on multisite / `wpmu_delete_user`:** hook both; same guard.
- **Annotating with only `annotation` and no `reasons`** (§4.3) is already supported by `annotate()` (`body['annotation']` alone).
- **`screen_registration()` when Account Defender is off / classic key:** `get_last_account_labels()` is empty → no-op; the block toggle is additionally gated on `is_active()`.
- **PowerPack duplicate-email path:** the module rejects duplicates before our hook; the Gmail-normalized *plugin-side* duplicate rejection (Phase 26 §6 roadmap idea) stays **out of scope** — with normalization feeding Account Defender (§4.1) and label blocking (§4.4), Google's clustering covers it without a parallel heuristic subsystem.

## 5. Verification checklist

1. `php -l` all touched PHP; `npm run build`; lint clean.
2. Staging (Beaver Builder + PowerPack 2.42.x, Enterprise key, Account defense enabled in console): human registration → assessment carries `accountId`; `user_register` stores the meta; first login annotates `LEGITIMATE` and clears it; deleting a never-logged-in test user annotates `FRAUDULENT` (verbose log lines for each).
3. Two dot-variant Gmail registrations produce the **same** accountId hash (log the hash under verbose to compare).
4. With `gswp_ad_block_signup` on and a simulated `SUSPICIOUS_ACCOUNT_CREATION` label (filtered response or mocked verifier), the PowerPack module renders the inline block message and no user row is created; alert email fires under the registration sub-toggle.
5. Auto-login-after-registration (module setting on): registration assessment is **not** annotated `CORRECT_PASSWORD`/`LEGITIMATE` by the login path (§4.2), and the first-login annotation still occurs on the *next* real login.
6. Non-Woo site with a deliberately bad API key: fail-open warning appears in `error_log` under WP_DEBUG.
7. Regression: wp-login.php login/lost-password, Woo login/registration/checkout, Xootix, PowerPack login byte-identical behaviour with the new toggles off.

## 6. Out of scope (roadmap)

- Plugin-side Gmail-duplicate rejection heuristic (see §4.7).
- Honeypot / gibberish-name scoring (Phase 26 §6, unchanged).
- Annotating historical/already-deleted spam accounts (no stored assessment names exist for them).
- Other page-builder registration forms (Elementor Pro etc.).
