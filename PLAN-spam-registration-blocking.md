# Implementation Plan — Block Spam Registrations Through the PowerPack Registration Form (Beaver Builder)

**Target version:** 2.11.0 (Phase 26)
**Feature:** Close the one registration surface the plugin does not score. Sites built with Beaver Builder + PowerPack can render user registration through PowerPack's **Registration Form module** — a different module from the Login Form module this plugin already integrates with. Registrations submitted through it are never scored, no matter which plugin toggles are on, so bots register freely (observed on onedog.solutions: gibberish first/last/website values and Gmail dot-trick addresses such as `de.lg.a.dod.an.i.e.l.bc@gmail.com`, arriving via the module's "The following user is registered on the site" admin notification email).

**Grounding:** Verified against the paid **PowerPack for Beaver Builder 2.42.3** source (`bbpowerpack/modules/pp-registration-form/`). All identifiers below are confirmed from that code, not inferred. The relevant files are `pp-registration-form.php` (module class `PPRegistrationFormModule`), `form-handler.php` (the admin-ajax handler), `includes/frontend.php` (rendered markup), and `js/frontend.js` (client submit).

## 0. Why the existing toggles don't catch this

| Existing surface | Hook | Covers the PP Registration Form? |
| --- | --- | --- |
| `gswp_enable_wp_register` (core) | `registration_errors` filter + `register_form` injection (`includes/class-gswp-login.php:49-52`) | **No** — confirmed: the module renders its own form and fires its own `pp_rf_form_start` / `pp_rf_form_end` actions, not core `register_form` (`includes/frontend.php:31,95`). It creates the user through its own admin-ajax action `pp_register_user`, so the wp-login.php pipeline never runs. |
| `gswp_enable_registration` (WooCommerce) | WooCommerce registration hooks | No — WooCommerce pipeline, unrelated. |
| Xootix popup integration | `xoo_el_process_registration_errors` (`includes/class-gswp-xootix.php:80`) | No — different plugin. |
| PowerPack integration | `pp_login_form_process_login_errors` + `wp_ajax_pp_lf_process_lost_pass` guard (`includes/class-gswp-powerpack.php:54-69`) | No — those are the **Login Form** module's hooks; the Registration Form module has its own render path and its own admin-ajax action (`pp_register_user`). |

So the fix is a fourth PowerPack hook-up inside the existing `GSWP_Powerpack` class, not a new subsystem.

## 1. What we already have (reused, not rebuilt)

| Plumbing | Where | Reused for |
| --- | --- | --- |
| Token scoring with per-form threshold, "unconfigured = allow" fail-open, and missing-token rejection; reads `$_POST['g-recaptcha-response']` by default | `GSWP_Verifier::verify_token()` (`includes/class-gswp-verifier.php:152-192`) | Called with the existing `wp_register` context / `register` action — same threshold option (`gswp_threshold_wp_register`). Our injected field is named `g-recaptcha-response`, so the default token read works with no extra args. |
| Account Defender identifier on registration assessments | `build_account_user_info()` whitelist already contains `wp_register` (`includes/class-gswp-verifier.php:897`) | Passing the submitted `user_email` as identifier gives Enterprise sites fake-signup labels on these registrations for free. |
| The "third-party forms reuse the WP core toggles" convention | Xootix (`class-gswp-xootix.php`) and PowerPack login (`class-gswp-powerpack.php`) doc blocks | Gate everything on `gswp_enable_wp_register` — **no new option**, no settings-UI change. |
| Shared API script + token refresh bootstrap (pre-fetch, 100 s refresh, tab-refocus, MutationObserver; vanilla JS, no jQuery) | `GSWP_Assets::enqueue_api_script()` / `add_refresh_bootstrap()` (`includes/class-gswp-assets.php:50-95`) | Keeps the injected hidden field populated on any Beaver Builder page. The module submits via `new FormData(form)` (`js/frontend.js:139`), which serializes every field inside the `<form class="pp-registration-form">`, so a hidden field injected inside it is posted automatically. |
| Hidden-field-inside-a-form injection driven by a plugin's own "form end" action | `GSWP_Xootix::inject_field()` on `xoo_el_form_end` (`includes/class-gswp-xootix.php:72,110-127`) | The Registration Form module exposes the exact analogue: `do_action( 'pp_rf_form_end', $settings )` fires inside the `<form>`, right before `</form>` (`includes/frontend.php:95-97`). Same pattern, no HTML-regex injection needed. |
| Module-captcha stripping so only our site-wide reCAPTCHA runs | `GSWP_Powerpack::replace_module_recaptcha()` (`includes/class-gswp-powerpack.php:88-110`) | Extended to also match `PPRegistrationFormModule` and strip its reCAPTCHA field (§3.5). |

## 2. Verified PowerPack internals (bbpowerpack 2.42.3)

Every placeholder in the previous revision of this plan is now confirmed against source:

| Fact | Confirmed value | Source |
| --- | --- | --- |
| Module class (for `fl_builder_render_module_content`) | `PPRegistrationFormModule` | `pp-registration-form.php:7` |
| Admin-ajax action that creates the user | `pp_register_user` (both `wp_ajax_` and `wp_ajax_nopriv_`) | `form-handler.php:48-49` |
| Nonce guarding that handler | `check_ajax_referer( 'pp-registration-nonce', 'security' )` runs first in the callback | `form-handler.php:66` |
| **Validation interception point** | `do_action( 'pp_rf_before_user_register', $userdata, $settings )` fires immediately before `wp_insert_user()` (`@since 2.32.x`) | `form-handler.php:254-257` |
| **Field-injection point** | `do_action( 'pp_rf_form_end', $settings )` fires inside the `<form>`, just before `</form>` | `includes/frontend.php:95-97` |
| Form element class (what FormData serializes) | `<form class="pp-registration-form" …>` | `pp-registration-form.php:254-257` (`get_form_attrs`), `js/frontend.js:139` |
| Client submit | `new FormData(form)` → `$.ajax` with `action=pp_register_user`; includes every field in the form | `js/frontend.js:139,314-326` |
| Submitted email field | `user_email` (present in `$userdata` at the `pp_rf_before_user_register` hook, after `stripslashes_deep`) | `form-handler.php:162-177,219-220,254` |
| Error response shape the module's JS renders | `wp_send_json_error( array( 'code' => …, 'message' => … ) )`; JS reads `response.data.message` for unknown codes and shows it in `.pp-rf-failed-error` | `form-handler.php:69-72` etc.; `js/frontend.js:347-359` |
| Module's own reCAPTCHA markup (to strip) | `<div class="pp-rf-field pp-rf-field-required" data-field-type="recaptcha"> … <div class="pp-grecaptcha" …></div> … <span class="pp-rf-error">…</span> </div>`, rendered only when `enable_recaptcha === 'yes'` | `includes/frontend.php:68-70`, `pp-registration-form.php:544-559`, `fields/recaptcha.php` |
| Module's own reCAPTCHA loader handle | `g-recaptcha` (via `$this->add_js('g-recaptcha', …)`) | `pp-registration-form.php:133-139` |
| Module JS skips its captcha safely when `.pp-grecaptcha` is absent | Guards on `reCaptchaFields.length > 0` / `reCaptchaField.length > 0` throughout | `js/frontend.js:7,281,302` |
| Conflict Guard already suppresses the `g-recaptcha` handle | `g-recaptcha` is in its suppression list | `includes/class-gswp-conflict-guard.php:50` |

## 3. Design decisions

1. **Extend `GSWP_Powerpack`, don't add a class.** Same third-party plugin, same verifier, same strip logic, same activation gate (`class_exists( 'BB_PowerPack' )`). The class doc block widens from "Login Form" to "Login Form and Registration Form modules".
2. **Gate on `gswp_enable_wp_register`, reuse `threshold_wp_register` via the `wp_register` context.** The established convention (Xootix registration does exactly this): zero new options, zero settings-UI / REST / MainWP-bridge changes, and one mental model — "the WordPress registration toggle protects every registration form on the site."
3. **Inject the hidden token field on the module's own `pp_rf_form_end` action** — the direct analogue of the Xootix `xoo_el_form_end` integration, so **no `fl_builder_render_module_content` HTML surgery is needed for injection**. The callback prints
   `<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="register" value="" />`
   and then calls `GSWP_Assets::enqueue_api_script()` + `add_refresh_bootstrap()` (footer scripts still emit when enqueued during content render — the same late-enqueue the login integration relies on at `class-gswp-login.php:140-143`). Guarded by a site-key check (`GSWP_Assets::site_key()` non-empty), matching every other injector, so a half-configured site never renders a dead field. Because the field sits inside `<form class="pp-registration-form">` and the module serializes with `FormData`, the token is posted with no client-side changes.
4. **Validate on the module's `pp_rf_before_user_register` action**, which fires after the nonce check and after all of the module's own validation, immediately before `wp_insert_user()`. The callback runs `verify_token( 'wp_register', 'register', array(), $userdata['user_email'] )` and, on a `WP_Error`, calls
   `wp_send_json_error( array( 'code' => 'gswp_recaptcha', 'message' => $result->get_error_message() ) )`.
   `wp_send_json_error()` ends the request (`wp_die()`), so **no user is created** on a failed score, and because our `code` is not in the module's client-side `errorCodes`/`messages.error` map the JS falls through to render our `message` in the form's `.pp-rf-failed-error` area (`js/frontend.js:347-359`). This is strictly cleaner than a raw admin-ajax guard: it runs *after* the nonce, has `$userdata` and `$settings` in hand, and short-circuits exactly the way the module itself does everywhere else.
   - **Version fallback:** `pp_rf_before_user_register` is `@since` PowerPack 2.32; the target site runs 2.42.3, so it is present. For older PowerPack, fall back to a priority-1 guard on `wp_ajax_pp_register_user` / `wp_ajax_nopriv_pp_register_user` (the `guard_lostpassword()` pattern) — functional but coarser (it runs before the module's nonce check). Detect with a capability probe or a documented minimum PowerPack version; primary path is the action hook.
5. **A bot that POSTs straight to admin-ajax is still blocked.** It must first satisfy `check_ajax_referer('pp-registration-nonce','security')` (scrapeable, so not our defense), then reach `pp_rf_before_user_register`, where a missing or low-scoring token is rejected by `verify_token()` (`class-gswp-verifier.php:187-192` for the missing-token branch). The nonce is the module's concern; the reCAPTCHA score is ours — same threat model as every other protected form.
6. **Strip the module's own reCAPTCHA when our protection is active**, extending `replace_module_recaptcha()` to also match `PPRegistrationFormModule` and remove the `data-field-type="recaptcha"` field block, then `wp_dequeue_script( 'g-recaptcha' )`. This is not just cosmetic here: **Conflict Guard already suppresses the `g-recaptcha` handle** (`class-gswp-conflict-guard.php:50`), so if an operator has the module's own reCAPTCHA enabled *and* Conflict Guard on, the module's captcha element renders but its script never loads — and the module's client-side gating (`js/frontend.js:281-291`) then blocks submit with "please check the captcha," locking out real users. Stripping the field removes `.pp-grecaptcha` from the DOM entirely, and the module's JS cleanly skips it (`js/frontend.js:7,281,302`), leaving our single site-wide reCAPTCHA as the only one. Gate: strip only when `gswp_enable_wp_register` is on (strip only the form we actually protect). The removal is anchored on the block's stable `data-field-type="recaptcha"` wrapper closing at `</span></div>`; confirm the exact regex against rendered output during implementation, since it is the one string-matching step in the change.
7. **Account Defender comes along for free.** The `wp_register` context is already whitelisted for `accountId` (`class-gswp-verifier.php:897`), so passing `user_email` as the identifier gives Enterprise sites fake-signup/account-farming labels with no extra work. No annotation code in this phase.
8. **Key-type note.** Our scoring is key-type agnostic (`GSWP_Assets` loads `enterprise.js` for Enterprise keys, `api.js` otherwise), so the readme's existing "PowerPack supports classic v3 keys only" caveat concerns the *module's own* captcha, not ours. Re-test under an Enterprise key (§7.6) and correct the readme only if that proves the caveat stale.

## 4. Changes by file

### 4.1 `includes/class-gswp-powerpack.php` (the whole feature)

- **Constructor:** inside the existing `class_exists( 'BB_PowerPack' )` gate, add a `gswp_enable_wp_register` block that registers:
  - `add_action( 'pp_rf_form_end', array( $this, 'inject_registration_field' ) );`
  - `add_action( 'pp_rf_before_user_register', array( $this, 'validate_registration' ), 10, 2 );`
  - the registration branch of the captcha-stripping filter (§4.4).
  Structurally identical to the two blocks already there.
- **New `inject_registration_field( $settings = null )`** — site-key check → print the hidden `g-recaptcha-response` field with `data-recaptcha-action="register"` → `GSWP_Assets::enqueue_api_script()` + `GSWP_Assets::add_refresh_bootstrap()`. (Idempotence isn't required since the module never emits our field itself, but a `static` guard against double-printing on pages with multiple form instances is cheap insurance; the bootstrap already handles multiple fields either way.)
- **New `validate_registration( $userdata, $settings )`** — read `$userdata['user_email']` (already sanitized/unslashed by the module), call `verify_token( 'wp_register', 'register', array(), $email )`, and on `WP_Error` respond with `wp_send_json_error( array( 'code' => 'gswp_recaptcha', 'message' => $result->get_error_message() ) )`. No nonce handling (the module already verified it); no `$_POST` sniffing beyond the email already handed to us.
- **`replace_module_recaptcha()`** — accept `PPRegistrationFormModule` in addition to `PPLoginFormModule`; when it's the registration module, strip the `data-field-type="recaptcha"` field block and `wp_dequeue_script( 'g-recaptcha' )`. Keep the per-feature gate (login stripping requires `gswp_enable_wp_login`, registration stripping requires `gswp_enable_wp_register`). Update its doc block to cover both modules.
- **Class doc block:** rewrite to describe both modules and both integration patterns (core-action piggyback for login/lost-password; the module's own `pp_rf_form_end` / `pp_rf_before_user_register` actions for registration).

### 4.2 Docs & version bump

- `readme.txt`: bump stable tag; extend the PowerPack feature mention (line 146) to include the Registration Form module; add the 2.11.0 changelog entry explaining the closed gap (registration through the PowerPack Registration Form module was previously never scored) and that it reuses the existing WordPress registration toggle and threshold.
- `google-security-for-wordpress.php`: plugin header + `GSWP_VERSION` → 2.11.0. No new options → no `gswp_default_options()` change; `gswp_maybe_migrate()` needs nothing beyond its automatic `gswp_db_version` restamp.
- `STATE.md`: append the Phase 26 section (modifications, key decisions, inertness notes) per convention.
- No `src/` (settings UI), REST, or MainWP-bridge changes — the reused toggle already flows through all three.

## 5. Edge cases & failure modes

- **Bot POSTs to `pp_register_user` with a scraped nonce but no token:** passes the module's nonce, reaches `pp_rf_before_user_register`, `verify_token()` returns `recaptcha_missing` → `wp_send_json_error` → no user created. Primary spam vector, closed.
- **Bot forges/replays a token:** fails Google verification (low score or invalid) at the same hook → blocked.
- **Site key configured but secret/project key missing:** `verify_token()` fail-opens (`class-gswp-verifier.php:167-178`) — registrations proceed, matching every other form. No new failure mode.
- **Toggle on but no Registration Form module on the page:** neither `pp_rf_form_end` nor `pp_rf_before_user_register` ever fires → fully inert, like the rest of the class.
- **Multiple registration modules on one page / module revealed dynamically:** each rendered instance fires `pp_rf_form_end` → its own hidden field; the shared bootstrap's `querySelectorAll` + MutationObserver keep every instance's token fresh (`class-gswp-assets.php:152-208`).
- **Long-idle page:** the 100-second refresh cycle plus tab-refocus refresh keeps the single-use token valid, so a slow-filling visitor is not rejected.
- **Module's own reCAPTCHA enabled + Conflict Guard on:** without stripping, the module's captcha element renders but its `g-recaptcha` script is suppressed → module JS blocks submit. §3.6 stripping removes the element so the module skips its captcha and only ours runs. When our toggle is off, the module's captcha is untouched.
- **`pp_rf_before_user_register` absent (PowerPack < 2.32):** covered by the §3.4 admin-ajax guard fallback; target site (2.42.3) uses the primary action hook.
- **Duplicate-email bot:** the module bails with "email exists" before our hook — the bot is blocked either way; only the surfaced message differs (cosmetic).
- **Auto-login / redirect post-registration actions:** they run only after `wp_insert_user()`, which our hook precedes, so they fire only for scored registrations. No interaction.
- **JS-disabled human:** rejected with the refresh-and-retry message — identical policy to the plugin's other protected forms; accepted trade-off.
- **False-positive rate:** governed by the existing `threshold_wp_register` (default 0.5), the same knob and FAQ guidance as every other registration surface.

## 6. Out of scope (noted for the roadmap)

- **Generic spam heuristics** — honeypot field, Gmail dot-normalization duplicate detection (`de.lg.a.…@gmail.com` ≡ `delga…@gmail.com`), gibberish-name scoring. Complementary to reCAPTCHA and form-agnostic, but a separate feature with its own settings surface.
- **Other page-builder registration forms** (Elementor Pro, Ultimate Addons, form-builder user-registration add-ons). Same integration pattern would apply; none are in use on One Dog sites today.
- **Cleanup of already-registered spam accounts** on affected sites — one-time manual task (Users → filter by role Subscriber, sort by registration date), not plugin behavior.
- **Site-operator hardening on onedog.solutions** (deployment note, not code): after updating, switch **Form Protection → WordPress registration** on; if the site doesn't actually need open registration, also unpublish the form and disable "Anyone can register" — the plugin should still close the gap for sites that do need it.

## 7. Verification checklist

1. `phpcs` clean; no `src/` rebuild needed (no admin-UI change).
2. On a staging site with Beaver Builder + PowerPack 2.42.x and a page using the Registration Form module, with `gswp_enable_wp_register` **off**: form renders and registers exactly as before (feature fully inert).
3. Toggle **on**, classic v3 key configured: page source shows one hidden `g-recaptcha-response` field with `data-recaptcha-action="register"` inside `<form class="pp-registration-form">`, and the reCAPTCHA API script is enqueued; a normal human registration succeeds and (verbose logging on) records a `wp_register` assessment.
4. **Bot path:** `curl` POST to `admin-ajax.php` with `action=pp_register_user`, a valid scraped nonce, and valid fields but no `g-recaptcha-response` → JSON error, **no user row created**. In a browser with the token field emptied via DevTools, the module renders our message inline in `.pp-rf-failed-error` rather than hanging.
5. **Threshold behavior:** with `threshold_wp_register` raised to 0.9 and a low-score token (automation browser), registration is blocked with the score message; at 0.1 it passes.
6. **Enterprise key:** token still generated via `enterprise.js` on the module page; with Account Defender on, the assessment carries `accountId` and any risk labels are logged. Re-test the readme's classic-keys caveat (§3.8) and correct the readme only if disproven.
7. **Module's own reCAPTCHA enabled** in its settings → its `data-field-type="recaptcha"` block and `g-recaptcha` script are gone from the rendered form while ours works; repeat with Conflict Guard on and confirm submit is no longer blocked. Login Form module on the same site still behaves exactly as in 2.10.0 (regression check on login + lost password).
8. Both `wp_ajax_` (logged-in) and `wp_ajax_nopriv_` (logged-out) registration paths are covered — the `pp_rf_before_user_register` hook fires for both since it lives inside the shared `register_user()` callback.
