# Implementation Plan — Block Spam Registrations Through the PowerPack Registration Form (Beaver Builder)

**Target version:** 2.11.0 (Phase 26)
**Feature:** Close the one registration surface the plugin does not score. Sites built with Beaver Builder + PowerPack can render user registration through PowerPack's **Registration Form module** — a different module from the Login Form module this plugin already integrates with. Registrations submitted through it are never scored, no matter which plugin toggles are on, so bots register freely (observed on onedog.solutions: gibberish first/last/website values and Gmail dot-trick addresses such as `de.lg.a.dod.an.i.e.l.bc@gmail.com`, arriving via the module's "The following user is registered on the site" admin notification email).

## 0. Why the existing toggles don't catch this

| Existing surface | Hook | Covers the PP Registration Form? |
| --- | --- | --- |
| `gswp_enable_wp_register` (core) | `registration_errors` filter + `register_form` injection (`includes/class-gswp-login.php:49-52`) | No — the module creates the user through its own admin-ajax handler; the wp-login.php pipeline never runs. |
| `gswp_enable_registration` (WooCommerce) | WooCommerce registration hooks | No — WooCommerce pipeline, unrelated. |
| Xootix popup integration | `xoo_el_process_registration_errors` (`includes/class-gswp-xootix.php:80`) | No — different plugin. |
| PowerPack integration | `pp_login_form_process_login_errors` + `wp_ajax_pp_lf_process_lost_pass` guard (`includes/class-gswp-powerpack.php:54-69`) | No — those are the **Login Form** module's hooks; the Registration Form module (`pp_rf_` prefix) has its own render path and its own admin-ajax action. |

So the fix is a fourth PowerPack hook-up inside the existing `GSWP_Powerpack` class, not a new subsystem.

## 1. What we already have (reused, not rebuilt)

| Plumbing | Where | Reused for |
| --- | --- | --- |
| Token scoring with per-form threshold, "unconfigured = allow" fail-open, and missing-token rejection | `GSWP_Verifier::verify_token()` (`includes/class-gswp-verifier.php:152-192`) | Called with the existing `wp_register` context / `register` action — same threshold option (`gswp_threshold_wp_register`) as every other registration form. |
| Account Defender identifier on registration assessments | `build_account_user_info()` whitelist already contains `wp_register` (`includes/class-gswp-verifier.php:897`) | Passing the submitted email as identifier gives Enterprise sites fake-signup labels on these registrations for free. |
| The "third-party forms reuse the WP core toggles" convention | Xootix (`class-gswp-xootix.php`) and PowerPack login (`class-gswp-powerpack.php`) doc blocks | Gate everything on `gswp_enable_wp_register` — **no new option**, no settings-UI change. |
| Shared API script + token refresh bootstrap (pre-fetch, 100 s refresh, tab-refocus, MutationObserver for dynamically revealed forms; vanilla JS, no jQuery) | `GSWP_Assets::enqueue_api_script()` / `add_refresh_bootstrap()` (`includes/class-gswp-assets.php:50-95`) | Keeps the injected hidden field populated on any Beaver Builder page. |
| Hidden-field markup convention (`name="g-recaptcha-response"` + `class="g-recaptcha-response"` + `data-recaptcha-action`) | `GSWP_Login::inject_field()` (`includes/class-gswp-login.php:124-144`) | The bootstrap targets `.g-recaptcha-response` generically, so an injected field in the module's form is picked up with zero new JS. |
| Early-priority admin-ajax guard pattern for a PowerPack action with no validation filter | `GSWP_Powerpack::guard_lostpassword()` (`includes/class-gswp-powerpack.php:63-68, 140-145`) | Template for the registration guard. |
| Module-captcha stripping so only our site-wide reCAPTCHA runs | `GSWP_Powerpack::replace_module_recaptcha()` (`includes/class-gswp-powerpack.php:88-110`) | Extended to also match the Registration Form module. |

## 2. Facts to verify against the installed PowerPack source (before writing code)

PowerPack for Beaver Builder is a premium plugin and is not vendored in this repo, so the exact identifiers below are inferred from its published `pp_rf_` prefix (its documented messages filter is [`pp_rf_custom_messages`](https://wpbeaveraddons.com/docs/powerpack/modules/registration-form/how-to-change-default-messages/)) and from the Login Form module's symmetry (`pp_lf_process_lost_pass`). **Each must be confirmed by grepping `wp-content/plugins/bb-powerpack/modules/pp-registration-form/` on a site that has it installed** (any One Dog site running PowerPack) and the plan's placeholders replaced:

1. **Admin-ajax action name** for form processing — expected `pp_rf_process_registration` (registered as both `wp_ajax_` and `wp_ajax_nopriv_`). Grep: `add_action( 'wp_ajax`.
2. **Whether a validation filter exists** analogous to `pp_login_form_process_login_errors`. If one exists, prefer it over the raw ajax guard (it surfaces errors through the module's own UI plumbing); if not, the priority-1 guard stands.
3. **Module class name** as seen by `fl_builder_render_module_content` — expected `PPRegistrationFormModule`. Grep: `class PP.*Module`.
4. **Rendered markup**: the `<form>` element's class/structure (for the injection insert point) and the captcha field-group classes (the Login Form module uses `pp-login-form-field pp-field-group pp-field-type-recaptcha`; the registration module's equivalents may differ). Needed for §3.3 and §3.4.
5. **Error response shape** the module's frontend JS renders — `guard_lostpassword()` uses `wp_send_json_error( $message )`; confirm the registration JS handles the same shape (grep the module's `frontend.js` for its `$.post`/fetch success handler) so a blocked bot — or a human with a broken token — sees the module's inline error, not a dead spinner.
6. **The submitted email's POST field name** (for the Account Defender identifier), and whether the payload is form-serialized (the Login Form module serializes with FormData, which is what carries our hidden field; confirm the registration module does the same).
7. **Whether the module fires the core `register_form` action** inside its markup (the Login Form module fires core `login_form`, which is how `GSWP_Login::inject_field()` reaches it). If it does, field injection may already happen when `gswp_enable_wp_register` is on, and §3.3's injection must detect the existing field and skip; if it doesn't, §3.3 is the only injection path. Handle both by making injection idempotent.

## 3. Design decisions

1. **Extend `GSWP_Powerpack`, don't add a class.** Same third-party plugin, same verifier, same strip logic, same activation gate (`class_exists( 'BB_PowerPack' )`). The class doc block's "Login Form" framing widens to "Login Form and Registration Form modules".
2. **Gate on `gswp_enable_wp_register`, reuse `threshold_wp_register` via the `wp_register` context.** This is the established convention (Xootix registration does exactly this), it means zero new options, zero settings-UI/REST/MainWP-bridge changes, and one mental model for operators: "the WordPress registration toggle protects every registration form on the site."
3. **Inject the hidden token field by filtering the module's rendered HTML** (`fl_builder_render_module_content`, matching the registration module class), appending `<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="register" value="" />` immediately before the form's closing tag, then enqueueing `GSWP_Assets::enqueue_api_script()` + `add_refresh_bootstrap()`. Injection is **idempotent**: if the markup already contains a `g-recaptcha-response` field (e.g. the module turns out to fire core `register_form`, §2.7), inject nothing and only ensure the assets are enqueued. Skip entirely when `GSWP_Assets::site_key()` is empty — the same guard every injector uses, so a half-configured site never renders a dead field.
4. **Validate in a priority-1 guard on the module's admin-ajax action** (both `wp_ajax_` and `wp_ajax_nopriv_`, since a logged-in admin can still exercise the form), mirroring `guard_lostpassword()`: call `verify_token( 'wp_register', 'register', array(), $email )` and, on `WP_Error`, end the request in the shape §2.5 confirms. Running before the module's own handler means the user is never created on a failed score, and a bot POSTing straight to admin-ajax without executing JS is rejected by the existing missing-token branch (`class-gswp-verifier.php:187-192`). If §2.2 turns up a real validation filter, use it instead and keep the guard out — filters compose better with the module's error rendering. We deliberately do not touch the module's nonce or other checks; the guard adds one veto, exactly like the lost-password precedent.
5. **Strip the module's own reCAPTCHA when ours is active**, extending `replace_module_recaptcha()` to also match the registration module class (with the §2.4-verified field-group classes; generalize the existing regex only as far as the verified markup requires). Same rationale as the login module: two captchas conflict, and the Conflict Guard may suppress their loader, which would otherwise fail their server-side check and block everyone. Rename the method's doc framing to cover both modules; behavior for the login module is unchanged.
6. **Account Defender comes along for free.** The `wp_register` context is already whitelisted for `accountId` (`class-gswp-verifier.php:897`), so Enterprise sites get fake-signup/account-farming labels on these registrations simply because the guard passes the submitted email as the identifier. No annotation work in this phase (registration outcomes are already handled the same way for the other registration surfaces).
7. **Keep the documented "classic v3 keys" caveat for PowerPack pages as-is** (readme line 146). Our own scoring is key-type agnostic (`GSWP_Assets` loads `enterprise.js` for Enterprise keys), so the caveat likely concerns only the module's *own* captcha settings — but re-testing PowerPack pages under an Enterprise key is a checklist item (§7.6), and the readme gets corrected only if that test proves it stale. Not a blocker for this feature.

## 4. Changes by file

### 4.1 `includes/class-gswp-powerpack.php` (the whole feature)

- **Constructor:** inside the existing `class_exists( 'BB_PowerPack' )` gate, add a `gswp_enable_wp_register` block registering (a) the render filter for injection + captcha stripping on the registration module and (b) the admin-ajax guard (or validation filter, per §2.2) — structurally identical to the two blocks already there.
- **New `inject_registration_field( $content, $module )`** on `fl_builder_render_module_content`: class check → site-key check → idempotence check (`g-recaptcha-response` already present?) → append hidden field before the form's closing tag → `GSWP_Assets::enqueue_api_script()` + `add_refresh_bootstrap()`. (The login module never needed this because core `login_form` fires inside it; registration gets its own injector unless §2.7 proves the same shortcut exists.)
- **New `guard_registration()`**: read the email from the verified POST field name, `verify_token( 'wp_register', 'register', array(), $email )`, and on error respond in the module's expected error shape. Sanitize with `sanitize_email()` / `wp_unslash()` and `// phpcs:ignore WordPress.Security.NonceVerification.Missing` with the same justification the lost-password guard carries (the module validates its own nonce afterwards; we only veto).
- **`replace_module_recaptcha()`**: accept both module classes; strip using the per-module verified markup classes. Gate stays per-feature: login stripping requires `gswp_enable_wp_login`, registration stripping requires `gswp_enable_wp_register` (strip only the form we actually protect).
- **Class doc block:** rewrite to describe both modules and both integration patterns (core-action piggyback for login/lost-password; render-filter injection + ajax guard for registration).

### 4.2 Docs & version bump

- `readme.txt`: bump stable tag; extend the PowerPack feature mention; add the 2.11.0 changelog entry explaining the closed gap (registration through the PowerPack Registration Form module was previously never scored) and that it reuses the existing WordPress registration toggle and threshold.
- `google-security-for-wordpress.php`: plugin header + `GSWP_VERSION` → 2.11.0. No new options → no `gswp_default_options()` change, and `gswp_maybe_migrate()` needs nothing beyond its automatic `gswp_db_version` restamp.
- `STATE.md`: append the Phase 26 section (modifications, key decisions, inertness notes) per convention.
- No `src/` (settings UI), REST, or MainWP-bridge changes — the reused toggle already flows through all three.

## 5. Edge cases & failure modes

- **Bot POSTs directly to admin-ajax, no JS executed:** no token in the payload → `recaptcha_missing` error → user never created. This is the primary spam vector and it dies at the guard.
- **Site key configured but secret/project key missing:** `verify_token()` fail-opens (`class-gswp-verifier.php:167-178`) — registrations proceed, matching every other form's behavior. No new failure mode.
- **Toggle on but PowerPack's registration module absent from any page:** hooks are registered but the ajax action never fires and the render filter never matches — inert, like the rest of the class.
- **Multiple registration modules on one page / module revealed dynamically:** each rendered instance gets its own hidden field; the shared bootstrap's `querySelectorAll` + MutationObserver keep every instance's token fresh (`class-gswp-assets.php:152-208`).
- **Long-idle page:** the 100-second refresh cycle (and tab-refocus refresh) keeps the single-use token valid, so a visitor who fills the form slowly is not rejected.
- **Operator had the module's own reCAPTCHA enabled:** stripped when our protection is on (§3.5), so there is exactly one captcha and one score; their own key config becomes irrelevant on that form. When our toggle is off, their captcha is untouched.
- **Beaver Builder editing mode:** `replace_module_recaptcha()` already runs on builder renders today for the login module without issue; keep behavior symmetrical. Verify while testing that the injected hidden input doesn't disturb the builder preview (it is `type="hidden"` — it shouldn't).
- **Auto-login / redirect post-registration actions:** the guard runs before the module creates the user, so its post-registration actions only ever fire for scored registrations. No interaction.
- **Legitimate user with JS disabled or blocked:** rejected with the refresh-and-retry message — identical to the plugin's other protected forms; accepted trade-off, unchanged policy.
- **False-positive rate:** controlled by the existing `threshold_wp_register` (default 0.5) — operators tune one threshold for all registration surfaces, per the readme's existing FAQ guidance.

## 6. Out of scope (noted for the roadmap)

- **Generic spam heuristics** — honeypot field, Gmail dot-normalization duplicate detection (`de.lg.a.…@gmail.com` ≡ `delga…@gmail.com`), gibberish-name scoring. Complementary to reCAPTCHA and form-agnostic, but a separate feature with its own settings surface.
- **Other page-builder registration forms** (Elementor Pro, Ultimate Addons, form-builder user-registration add-ons). Same integration pattern would apply; none are in use on One Dog sites today.
- **Cleanup of already-registered spam accounts** on affected sites — one-time manual task (Users → filter by role Subscriber, sort by registration date), not plugin behavior.
- **Site-operator hardening on onedog.solutions** (deployment note, not code): after updating, switch **Form Protection → WordPress registration** on; if the site doesn't actually need open registration, also unpublish the form and disable "Anyone can register" — the plugin should still close the gap for sites that do need it.

## 7. Verification checklist

1. **§2 verification pass first:** every placeholder identifier (ajax action, module class, markup classes, error shape, email field, `register_form` firing) confirmed against the installed PowerPack source and recorded in the code comments before implementation is considered final.
2. `phpcs` clean; no `src/` rebuild needed (no admin-UI change).
3. On a staging site with Beaver Builder + PowerPack and a page using the Registration Form module, with `gswp_enable_wp_register` **off**: form renders and registers exactly as before (feature fully inert).
4. Toggle **on**, classic v3 key configured: page source shows one hidden `g-recaptcha-response` field with `data-recaptcha-action="register"` inside the module's form and the `google-recaptcha-v3` script enqueued; a normal human registration succeeds and (verbose logging on) records a `wp_register` assessment.
5. **Bot path:** `curl` POST to the module's admin-ajax action with valid form fields but no token → registration rejected, no user row created, and the module UI (when driven from a browser with the token field emptied via DevTools) renders the error inline rather than hanging.
6. Enterprise key: token still generated via `enterprise.js` on the module page; with Account Defender on, the assessment carries `accountId` and any risk labels are logged. Re-test the readme's classic-keys caveat (§3.7) and correct the readme only if disproven.
7. Module's own reCAPTCHA enabled in its settings → its captcha markup and loader are gone from the rendered form while ours works; Login Form module on the same site still behaves exactly as in 2.10.0 (regression check on login + lost password).
8. Threshold behavior: with `threshold_wp_register` raised to 0.9 and a low-score token (automation browser), registration is blocked with the score message; at 0.1 it passes.
9. `wp_ajax_` (logged-in) and `wp_ajax_nopriv_` variants both guarded.
