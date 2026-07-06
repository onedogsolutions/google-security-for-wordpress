# Implementation Plan — Admin Email Alerts on Flagged Events

**Target version:** 2.7.0 (Phase 20)
**Feature:** Send the site operator one email when something the plugin already detects actually matters: Account Defender flags `SUSPICIOUS_LOGIN_ACTIVITY` on an **admin-capable account**, or Transaction Defense **blocks a checkout**. Today both outcomes only land in the WooCommerce log (`wc-logs`, source `gswp`) that nobody watches. For an agency running many sites this is the difference between finding out during the incident and finding out from the client. The hard requirement is throttling: a credential-stuffing run or a bot hammering checkout must produce a handful of emails, never hundreds.

---

## 1. What we already have (reused, not rebuilt)

| Plumbing | Where | Reused for |
| --- | --- | --- |
| Suspicious-login detection: labels captured per login, `SUSPICIOUS_LOGIN_ACTIVITY` already isolated for logging/step-up | `GSWP_Account_Defender::capture_login_assessment()` (`includes/class-gswp-account-defender.php:165-197`) | The login alert fires from the same spot the log line does. |
| Checkout block — classic checkout | `GSWP_Verifier::process_fraud_prevention()` block branch (`includes/class-gswp-verifier.php:789-798`) | The checkout alert fires alongside the existing "blocked checkout" log line. |
| Checkout block — WooCommerce Checkout block / Store API | `GSWP_Blocks::validate_store_checkout()` block branch (`includes/class-gswp-blocks.php:151-159`) | Same event, second entry point. |
| Assessment context: transaction risk, threshold, assessment resource name, billing/order data | `GSWP_Verifier` getters (`get_last_fraud_risk()`, `get_last_assessment_name()`), `$order` in the Blocks path, `$_POST` billing fields in the classic path | Email body content. |
| Settings wiring pattern (option → `gswp_default_options()` → REST get/update → admin localizer → `App.jsx` → panel component) | `google-security-for-wordpress.php:105`, `includes/class-gswp-rest-api.php`, `includes/class-gswp-admin.php:~90-110`, `src/components/*` | All new settings. |
| Fail-open logging helper | `static_log()` in `GSWP_Account_Defender` / `log()` in the verifier | Alert-send failures are logged, never surfaced to the visitor. |

## 2. Design decisions

1. **Decouple detection from delivery with internal action hooks.** The two detection sites fire plain WordPress actions — `do_action( 'gswp_suspicious_admin_login', $user, $labels, $context )` and `do_action( 'gswp_checkout_blocked', $risk, $threshold, $context )` — and a new `GSWP_Alerts` class is the only subscriber we ship. This keeps the verifier/defender classes free of mail logic, and gives agencies a free extension point (pipe the same events to Slack/ticketing without touching the plugin).
2. **Opt-in, off by default** (`gswp_alerts`, default `'0'`), consistent with every other behaviour-adding toggle in the plugin. Both event sources are Enterprise-only features, so the settings panel shows the same "requires an Enterprise key" notice pattern as `TransactionDefense.jsx` when the key type is classic.
3. **Admin account = `manage_options`** (the plugin's own capability bar for its settings), checked via `user_can()`, filterable via `gswp_alert_login_capability`. At `authenticate` priority 40 the `$user` arg is a `WP_User` when the password was correct; when it wasn't (credential stuffing — exactly the case we care about) we resolve the target with `get_user_by( 'login', $username ) ?: get_user_by( 'email', $username )`. Unresolvable username → not an admin account → no alert. The alert fires **independently of the step-up setting** (`gswp_ad_step_up`); whether a step-up was forced is reported *in* the email, not a precondition for it.
4. **Alerting is fail-open and off the critical path.** A `wp_mail()` failure (or a slow SMTP plugin) must never delay or break a login or checkout response. Events are recorded at detection time; actual sending happens on the `shutdown` hook, after the response is decided. Send failures are logged under verbose logging and otherwise ignored.
5. **Two-layer throttling — per-event dedupe plus a global circuit breaker** (see §3). This is the core of the feature:
   - *Per-event dedupe* ("once-per-event"): each event carries a dedupe key; a transient (`gswp_alert_sent_{md5(key)}`) suppresses repeats of the *same* event within its window. Ten wrong-password attempts against the same admin in an hour = one email.
   - *Global circuit breaker*: an hourly counter transient caps immediate sends (default **5 emails/hour**, filter `gswp_alert_hourly_cap`). Once the cap is hit, further events are appended to a queue instead of mailed, and the digest cron flushes them as **one** summary email. Distinct events can therefore never produce unbounded mail either.
6. **One mode select, not mode + frequency.** `gswp_alert_mode` ∈ `immediate` (default) | `hourly` | `daily`. In `immediate` mode events mail as they happen (subject to §5 throttling, with the digest as overflow). In `hourly`/`daily` mode nothing mails immediately — everything queues and the cron sends one digest per period *only when the queue is non-empty* (an empty period sends nothing; "no news" emails are spam too).
7. **Plain-text email.** No HTML template to maintain, renders everywhere, forwards cleanly into ticketing systems. Site name + URL lead the subject and body since the recipient manages many sites: `[{blogname}] Suspicious login to admin account "ryan"` / `[{blogname}] High-risk checkout blocked (risk 0.91)`.
8. **Recipients**: `gswp_alert_email`, a comma-separated list, each entry `sanitize_email()`-validated; empty (default) falls back to `get_option( 'admin_email' )`. Agencies point it at a shared monitoring inbox.
9. **Queue in a single autoload-off option** (`gswp_alert_queue`), capped at 100 entries with a dropped-count so the digest can say "…and 214 more blocked checkouts". No custom table; the queue is transient working data, not an audit log (the wc-log remains the log).

## 3. Event & throttle matrix

| Event | Fired from | Dedupe key | Dedupe window (filterable) | Payload captured |
| --- | --- | --- | --- | --- |
| `suspicious_admin_login` | `GSWP_Account_Defender::capture_login_assessment()` — when `SUSPICIOUS_LOGIN_ACTIVITY` ∈ labels **and** resolved user passes the capability check | `login_{user_id}` | 6 h — repeated flags on the same account collapse | user login + display name, roles, whether the password was correct, whether 2FA step-up was forced (`gswp_ad_step_up` on + user enrolled), full label list, IP (`REMOTE_ADDR`), user agent, timestamp, assessment resource name |
| `checkout_blocked` | `GSWP_Verifier::process_fraud_prevention()` (classic) and `GSWP_Blocks::validate_store_checkout()` (Store API) — inside the existing `risk >= threshold` branches, right after the existing log call | `checkout_{md5(billing_email ?: REMOTE_ADDR)}` | 1 h — one email per attacker identity per hour, however many retries | risk vs threshold, billing name + email, cart/order total + currency, source (`classic` / `block`), IP, timestamp, assessment resource name (for cross-referencing in the GCP console) |

Throttle pipeline (identical for both events):

```
event fires
  └─ dedupe transient for key exists?  ── yes → increment its suppressed-count, done
  └─ mode is hourly/daily?             ── yes → append to queue (digest cron mails it)
  └─ hourly send counter ≥ cap?        ── yes → append to queue (overflow digest)
  └─ else: set dedupe transient, increment counter, queue for send at `shutdown`
```

The dedupe transient stores a suppressed-count that the *next* email or digest reports ("3 further flagged logins for this account were suppressed"), so throttled ≠ invisible.

## 4. Changes by file

### 4.1 New `includes/class-gswp-alerts.php` (`GSWP_Alerts`)

Constructed in `gswp_init()` (no constructor args needed). Constructor bails unless `enabled()` (`'1' === get_option( 'gswp_alerts', '0' )` — note alerts do **not** require Transaction Defense/Account Defender to be re-checked here; if the source features are off, the actions simply never fire). Hooks:

- `add_action( 'gswp_suspicious_admin_login', …, 10, 3 )` / `add_action( 'gswp_checkout_blocked', …, 10, 3 )` → normalize into an event array (`type`, `key`, `time`, `data`), run the §3 throttle pipeline.
- `add_action( 'shutdown', 'flush_immediate' )` → `wp_mail()` any events accepted for immediate send this request.
- Digest cron: a custom schedule is unnecessary — WP ships `hourly` and `daily`. `init` handler ensures `gswp_alerts_digest_event` is scheduled with the configured recurrence whenever mode ≠ immediate **or** the overflow queue is non-empty (immediate mode schedules it lazily, `hourly`, only while overflow exists, and the handler unschedules itself when the queue drains). Reschedule on mode change (handled in the REST route by clearing the event; next `init` re-schedules).
- `send_digest()`: reads + clears `gswp_alert_queue` atomically-enough (read, `update_option` to empty, then format), groups by type, one email: per-type counts, up to ~10 detail lines each, "+N more", dropped-count if the cap was hit.
- Formatting helpers `format_login_event()` / `format_checkout_event()` shared by single and digest emails.
- Recipient resolution `recipients()`: parse `gswp_alert_email`, validate, fall back to `admin_email`.
- Everything static-friendly and fail-open; wp_mail return false → `static_log()` under verbose.

### 4.2 `includes/class-gswp-account-defender.php`

In `capture_login_assessment()`, inside the existing `SUSPICIOUS_LOGIN_ACTIVITY` handling (independent of the `gswp_ad_step_up` branch at `:191`):

- Resolve the target account (decision 3): `$user` if `WP_User`, else `get_user_by()` on `$username`.
- If it passes `user_can( $target, apply_filters( 'gswp_alert_login_capability', 'manage_options' ) )`, fire `do_action( 'gswp_suspicious_admin_login', $target, $labels, array( 'correct_password' => $user instanceof WP_User, 'step_up' => self::$force_2fa, 'assessment' => $name, 'ip' => …, 'ua' => … ) )`.
- The action fires whether or not alerts are enabled (cheap, and third parties may listen); `GSWP_Alerts` simply isn't hooked when disabled.

### 4.3 `includes/class-gswp-verifier.php`

In `process_fraud_prevention()`, inside the `$risk >= $threshold` block (after the existing `$this->log(...)` at `:792`): fire `do_action( 'gswp_checkout_blocked', $risk, $threshold, array( 'source' => 'classic', 'assessment' => $this->last_assessment_name, billing/cart fields from the already-sanitized checkout data ) )`. No behaviour change to the block itself.

### 4.4 `includes/class-gswp-blocks.php`

Same one-liner in `validate_store_checkout()`'s block branch (after `:154`), with `'source' => 'block'` and billing/total pulled from the `$order` we already hold. Fire **before** `$this->fail()` throws.

### 4.5 `google-security-for-wordpress.php`

- `require` + construct `GSWP_Alerts` in `gswp_init()`.
- `gswp_default_options()`: `'alerts' => '0'`, `'alert_email' => ''`, `'alert_mode' => 'immediate'`, `'alert_login' => '1'`, `'alert_checkout' => '1'` (the two per-event sub-toggles let a store that expects checkout blocks keep only the login alarm, and vice versa).
- `register_deactivation_hook` → new `gswp_deactivate()`: `wp_clear_scheduled_hook( 'gswp_alerts_digest_event' )` (the plugin currently has no deactivation hook; add one).

### 4.6 `includes/class-gswp-rest-api.php`

- `get_settings()`: expose `alerts`, `alert_email`, `alert_mode`, `alert_login`, `alert_checkout`.
- `update_settings()`: add `alerts`, `alert_login`, `alert_checkout` to the `$toggles` array; `alert_email` = split on comma, `sanitize_email()` each, drop invalids, re-join; `alert_mode` whitelist `array( 'immediate', 'hourly', 'daily' )` (mirror the `conflict_mode` pattern at `:170-175`). On mode change, `wp_clear_scheduled_hook( 'gswp_alerts_digest_event' )` so the next `init` reschedules at the new recurrence.

### 4.7 `includes/class-gswp-admin.php`

Localizer: add the five new settings alongside the existing ones (`:103` area).

### 4.8 React UI

- New `src/components/AlertSettings.jsx` — "Email Alerts" panel: master toggle; recipients text input with "defaults to the site admin email; separate multiple addresses with commas" help text; delivery select (Immediately / Hourly digest / Daily digest); two event checkboxes ("Suspicious login on an administrator account", "Blocked high-risk checkout" — the latter rendered only when `woocommerceActive`); classic-key notice when `key_type !== 'enterprise'` explaining both alert sources are Enterprise features.
- `src/components/App.jsx`: defaults for the five settings, render the panel, include fields in the save payload.
- `npm run build`.

### 4.9 Docs & version bump

`readme.txt` (stable tag, feature bullet, changelog), main file header + `GSWP_VERSION`, `package.json` + `package-lock.json` root → **2.7.0**. Append Phase 20 section to `STATE.md`.

## 5. Edge cases & failure modes

- **Login-path latency:** `wp_mail` on a slow SMTP plugin can add seconds; sending at `shutdown` (decision 4) keeps the `authenticate` filter and checkout validation fast. Note: on the classic checkout the blocked response is an AJAX error — `shutdown` still runs after output, so no visitor-visible delay.
- **Bot hammering checkout with rotating emails:** per-event dedupe won't match (keys differ) — this is exactly what the global circuit breaker catches: 5 immediate emails, then one overflow digest per hour with counts.
- **`wp_mail` unavailable/failing (misconfigured SMTP):** logged under verbose, event stays in the queue only for digest sends (immediate failures are not retried — retrying mail from a security plugin risks its own spam loop; the wc-log remains the source of truth).
- **Digest cron on low-traffic sites:** WP-Cron only fires on visits; an hourly digest may arrive late. Acceptable — document in the readme FAQ; agencies with real cron (`DISABLE_WP_CRON` + system cron) get exact timing.
- **Queue race (two blocked checkouts in the same second):** read-modify-write on `gswp_alert_queue` can lose an entry under true concurrency. Accepted for v1 (worst case: one line missing from a digest; the counts come from dedupe transients too). Not worth an SQL-level guard for advisory email.
- **Recipient validation:** every configured address invalid → fall back to `admin_email`, never send to nobody silently.
- **PII:** billing name/email in the checkout alert goes to the site's own operator — same data visible on any order screen; no new exposure. The login alert contains no password material.
- **Multisite:** per-site options/queue/cron, per-site `admin_email` fallback. No network-level aggregation (out of scope).

## 6. Out of scope (noted for the roadmap)

- Slack/webhook delivery — the `gswp_suspicious_admin_login` / `gswp_checkout_blocked` actions are the deliberate seam for it; a later phase (or a site snippet) can subscribe without core changes.
- Alerts for non-admin suspicious logins, `SUSPICIOUS_ACCOUNT_CREATION`, or account-modification events — the action-hook pattern makes each a small follow-up.
- A cross-site agency dashboard aggregating alerts from many installs.
- HTML email templates.

## 7. Verification checklist

1. `php -l` on every touched PHP file; `npm run build` + `wp-scripts lint-js` clean.
2. Settings round-trip: toggle/enter each new setting, save, reload — values persist; invalid email dropped; mode change reschedules cron (`wp cron event list`).
3. Suspicious admin login (simulate by short-circuiting the label check or via a filter on the labels array in a dev mu-plugin): admin account → one email with correct context; second flagged login inside the window → no second email, suppressed-count appears in the next digest/email; non-admin account → no email.
4. Blocked checkout on **both** paths (classic shortcode + Checkout block, threshold set to 0.0 with blocking on): one email each with `source` correct; repeat attempts with the same billing email inside an hour → one email.
5. Circuit breaker: fire >5 distinct events in an hour (loop in dev) → 5 immediate emails + overflow queued; `wp cron event run gswp_alerts_digest_event` → single digest with the remainder.
6. Digest modes: switch to hourly/daily → no immediate emails; cron run sends one summary; empty queue → cron sends nothing.
7. Alerts disabled (default) → actions still fire (verify with a test listener), no email ever sent.
8. Deactivate plugin → `gswp_alerts_digest_event` cleared.
