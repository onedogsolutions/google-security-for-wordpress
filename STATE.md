# State Tracker - Google Security for WordPress

## Current Phase: Phase 8 (Fix 2FA login flow across all entry points + admin UI tweaks)

### Phase 8 Modifications
- Fixed a fatal error (HTTP 500) when an enrolled user logged in from a non-`wp-login.php` form (e.g. the WooCommerce "My Account" page). `GSWP_Two_Factor::maybe_start_challenge()` previously rendered the interstitial inline by calling `login_header()`/`login_footer()`, which only exist inside `wp-login.php`; on a front-end login they are undefined and fatal. The challenge is now always rendered on `wp-login.php`: `maybe_start_challenge()` clears the freshly issued auth cookie, stashes the in-progress login behind a single-use, HTTP-only cookie token (`gswp_2fa_pending`) backed by a 5-minute transient, and `wp_safe_redirect()`s to `wp-login.php?action=gswp_2fa`.
- Closed a 2FA bypass on AJAX logins (the PowerPack Login Form module). `maybe_start_challenge()` used to `return` early on `wp_doing_ajax()`, leaving the auth cookie in place so the user was logged in with no second factor. It now clears the auth cookie and sets the pending cookie for AJAX logins too; a new `maybe_resume_challenge()` guard (hooked to both `login_init` and `template_redirect`) detects a logged-out visitor carrying a valid pending cookie and redirects them to the interstitial, so the half-finished AJAX login is forced through 2FA on the next page load.
- Replaced the per-user login-nonce mechanism (`create_login_nonce()`/`verify_login_nonce()`, stored in user meta) with the cookie-token + transient "pending login" helpers (`store_pending_login()`, `get_pending_login()`, `clear_pending_login()`, `challenge_url()`, `cookie_path()`). The token is unguessable and HTTP-only, so it can only be minted by a successful password check, and the TOTP code is still required. `show_challenge()` no longer emits hidden `user_id`/`nonce`/`redirect`/`rememberme` fields (the cookie carries that state).
- The post-2FA redirect now honours both `redirect_to` (wp-login.php) and `redirect` (WooCommerce My Account) request fields.
- Admin settings screen (React): `TwoFactorNotice` now shows a "Two-Factor Authentication Settings" button linking to Settings → Two-Factor Auth (new `twoFactorSettingsUrl` localized from `GSWP_Admin`), placed above the "Set up 2FA from your user profile" link. Both button-styled links carry a `gswp-2fa-btn` class with a scoped CSS rule in `src/styles/index.css` forcing white text (including `:hover`/`:focus`), since WordPress admin's own `a` colour rules otherwise won over Tailwind's `text-white`.

## Historical Phase: Phase 7 (Remove Key Scavenger + 2FA Profile Notice + Legacy Plugin Takeover)

### Phase 7 Modifications
- Removed the Smart Key Scavenger entirely: deleted `includes/class-gswp-key-scavenger.php` and `src/components/KeyScavenger.jsx`, dropped the `POST /gswp/v1/scan-keys` REST route and its `scavenge_keys()` callback, and removed the scavenger require/import wiring from the main file and `App.jsx`.
- Added `src/components/TwoFactorNotice.jsx`: a dialogue/notice panel on the settings screen explaining that 2FA enrolment happens in the user Profile, with a button linking to `profile.php#gswp-2fa`. The admin localizer now passes a `profileUrl` to the React app.
- Renamed the settings menu/page from "reCAPTCHA v3" to "Google Security" (`includes/class-gswp-admin.php`) and updated the React header accordingly.
- On activation (`gswp_activate`), the plugin now imports the predecessor "Google reCAPTCHA v3 for WooCommerce" plugin's `recaptcha_woo_*` options into the `gswp_*` keys via the shared `gswp_import_legacy_options()`, then deactivates and deletes that old plugin (matched by basename `google-recaptcha-v3-for-woocommerce/...`, text domain, or plugin name) with `deactivate_plugins()` + `delete_plugins()`. `gswp_maybe_migrate()` still imports options on every load as an upgrade safety net (without touching plugin files).

## Historical Phase: Phase 6 (Rebrand to Google Security for WordPress + Two-Factor Authentication)

### Phase 6 Modifications (v2.0.0)
- Renamed the plugin from "Google reCAPTCHA v3 for WooCommerce" to "Google Security for WordPress". Renamed the main file to `google-security-for-wordpress.php` and all `includes/class-recaptcha-woo-*.php` files to `includes/class-gswp-*.php`.
- Renamed all internal identifiers: text domain/slug -> `google-security-for-wordpress`; constants `RECAPTCHA_WOO_*` -> `GSWP_*`; class prefix `Recaptcha_Woo_*` -> `GSWP_*`; option/function prefix `recaptcha_woo_*` -> `gswp_*`; REST namespace `recaptcha-woo/v1` -> `gswp/v1`; JS globals/handles/IDs accordingly. Google's own field names (`g-recaptcha-response`, `data-recaptcha-action`, the `google-recaptcha-v3` script handle) were left untouched.
- Added `gswp_maybe_migrate()` (on `plugins_loaded`): one-time copy of legacy `recaptcha_woo_*` options to the new `gswp_*` keys so existing installs keep their settings. Old options are left in place as a safety net.
- Added `includes/class-gswp-totp.php`: self-contained RFC 6238 TOTP / RFC 4226 HOTP engine with Base32 (RFC 4648) secrets. Verified against the official RFC 6238 SHA-1 test vectors.
- Added `includes/class-gswp-two-factor.php`: per-user enrolment on the profile screen (QR via in-browser `qrcode-generator` with a manual setup-key fallback, filterable via `gswp_2fa_qr_script_url`), an interstitial login challenge after the password check (`wp_login` + `login_form_gswp_2fa`, mirroring the Two-Factor feature plugin), single-use hashed backup codes, replay protection via the last-used time step, admin reset of another user's 2FA, optional role-based enforcement, and an XML-RPC block for enrolled accounts.
- Added `includes/class-gswp-two-factor-admin.php`: server-rendered Settings -> Two-Factor Auth page (master toggle + per-role enforcement) using the Settings API (no build step required).
- Bumped version to 2.0.0 across the main file header, `GSWP_VERSION`, `readme.txt`, and `package.json`; refreshed the readme description, features, FAQ, and changelog.

## Current Phase (historical): Phase 5 (Project Finalization & Artifact Bundling)

### Modifications Done
- Created `.gitignore` to prevent tracking of development artifacts (like `node_modules` and compiled zips).
- Updated `package.json` to pin stable releases of Tailwind CSS (`^4.0.0`) and `@tailwindcss/postcss` (`^4.0.0`), and added linting scripts.
- Added `webpack.config.js` extending WordPress's default scripts configuration to bundle JavaScript and extract CSS correctly.
- Created `google-security-for-wordpress.php` (main bootstrap file).
- Created `includes/class-gswp-key-scavenger.php` to scan and scavenge keys from Fluent Forms, Gravity Forms, Beaver Builder options, and Beaver Builder postmeta.
- Created `includes/class-gswp-admin.php` to register the submenu under WooCommerce settings and enqueue React entrypoints using localizing scripts.
- Created `includes/class-gswp-rest-api.php` exposing `GET /settings`, `POST /settings` (with page-specific score thresholds), and `GET /scavenge`.
- Created React components `src/components/App.jsx`, `src/components/SettingsPanel.jsx`, `src/components/PageToggles.jsx`, `src/components/KeyScavenger.jsx`, `src/components/StatusBadge.jsx`, and Webpack entrypoint `src/index.js`.
- Created `src/styles/index.css` defining the scoped Tailwind v4 styling.
- Installed node module dependencies (`npm install`).
- Compiled assets with webpack successfully (`npm run build`).
- Created `includes/class-gswp-frontend.php` to inject the Google API scripts and hidden inputs onto WooCommerce login, registration, and checkout screens.
- Created `includes/class-gswp-verifier.php` to validate incoming reCAPTCHA tokens server-side using Google API and WP_Error handling.
- Created standard plugin meta file `readme.txt`.
- Optimized the database key scavenger flow: replaced the automatic, on-load database scanning query with an explicit user-triggered manual scan (`POST /gswp/v1/scan-keys`).
- Added check for `fluentform_settings` option within the key scavenger logic.
- Introduced interactive frontend states (`isScanning`, `scanPerformed`, `discoveredData`) with user controls styled using Tailwind v4.
- Reworked frontend token handling (v1.1.0): tokens are pre-fetched on page load and refreshed before the two-minute expiry, on `updated_checkout`, on `checkout_error`, and on tab refocus, so gateway-driven submissions (Stripe UPE, PayPal PPCP) always carry a valid token. Inline JS now attaches via `wp_add_inline_script` so it is never duplicated inside AJAX checkout fragments. The bootstrap is dependency-free vanilla JS (no jQuery): fragment replacements and checkout error notices are detected with a MutationObserver, and WooCommerce's jQuery checkout events (`updated_checkout`, `checkout_error`, `checkout_place_order` veto) are bound only as a progressive enhancement when jQuery is present.
- Added reCAPTCHA Enterprise support (v1.1.0): new `key_type`, `gcp_project_id`, and `gcp_api_key` settings; frontend loads `enterprise.js` and uses `grecaptcha.enterprise`; verifier creates assessments via `recaptchaenterprise.googleapis.com` with expected-action checking.
- Hardened verification failure modes (v1.1.0): credential misconfiguration (invalid secret, bad API key/project) logs a warning to the WooCommerce logger and fails open instead of blocking customers; expired/duplicate tokens return a dedicated "verification expired" message.
- Added WordPress core screen support (v1.3.0): new `includes/class-gswp-login.php` scores the wp-login.php sign in (`authenticate` filter), user registration (`registration_errors` filter), and lost password (`lostpassword_post` action) forms, each with its own threshold. Scripts and the token bootstrap are emitted directly in `login_footer` since wp-login.php skips the standard enqueue pipeline.
- Made WooCommerce optional (v1.3.0): removed the `Requires Plugins: woocommerce` header, moved the settings page from the WooCommerce submenu to Settings -> reCAPTCHA v3 (`add_options_page`), switched the capability/REST permission from `manage_woocommerce` to `manage_options`, and gated the WooCommerce form toggles in the admin UI behind a `woocommerceActive` flag.
- Added shared `includes/class-gswp-assets.php` (v1.3.0): centralizes the Google API script enqueue (classic/enterprise) and a reusable, vanilla-JS token refresh bootstrap that keeps every `.g-recaptcha-response` field populated (on load, before expiry, on refocus, and via MutationObserver for dynamically added fields).
- Added Login/Signup Popup integration (v1.3.0): `includes/class-gswp-xootix.php` injects the token field via the plugin's `xoo_el_form_end` template action and validates through its `xoo_el_process_login_errors` / `xoo_el_process_registration_errors` / `xoo_el_process_lostpw_errors` filters, reusing the WordPress core toggles, thresholds, and verifier. Inert unless `easy-login-woocommerce` is active.
- Added reCAPTCHA conflict handling (v1.3.0): `includes/class-gswp-conflict-guard.php` suppresses other plugins' reCAPTCHA scripts via the `script_loader_tag` filter so this implementation is the only one on the page. New `gswp_conflict_mode` option (`off` / `active` / `site`) surfaced as a "reCAPTCHA Conflict Handling" radio panel (`src/components/Compatibility.jsx`). Matches the Gravity Forms handles from the old manual snippet plus any script whose src loads google.com/recaptcha, generalizing it beyond a single page. `active` mode only strips others where this plugin's own script is enqueued.
- Added PowerPack (Beaver Builder) Login Form integration (v1.3.0): `includes/class-gswp-powerpack.php`. The module fires the core `login_form` / `lostpassword_form` actions (so `GSWP_Login` injects the field) and serializes the whole form with FormData (so the token is sent). Login is validated through the module's `pp_login_form_process_login_errors` filter; lost password has no filter, so its `pp_lf_process_lost_pass` admin-ajax action is guarded at priority 1. `GSWP_Login::inject_field()` now also loads the shared API script + token bootstrap when injecting on a front-end form (not wp-login.php). When login protection is enabled, `replace_module_recaptcha()` (hooked to `fl_builder_render_module_content`) strips the module's own reCAPTCHA/hCaptcha field and dequeues its `g-recaptcha`/`h-captcha` loaders so this plugin's site-wide reCAPTCHA is the only one on the form. Inert unless `BB_PowerPack` is active.

### Files Created/Modified
- [x] [.gitignore](file:///Users/rwaterbury/Developer/google-security-for-wordpress/.gitignore)
- [x] [package.json](file:///Users/rwaterbury/Developer/google-security-for-wordpress/package.json)
- [x] [webpack.config.js](file:///Users/rwaterbury/Developer/google-security-for-wordpress/webpack.config.js)
- [x] [google-security-for-wordpress.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/google-security-for-wordpress.php)
- [x] [includes/class-gswp-key-scavenger.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-key-scavenger.php)
- [x] [includes/class-gswp-admin.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-admin.php)
- [x] [includes/class-gswp-rest-api.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-rest-api.php)
- [x] [src/index.js](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/index.js)
- [x] [src/components/App.jsx](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/components/App.jsx)
- [x] [src/components/SettingsPanel.jsx](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/components/SettingsPanel.jsx)
- [x] [src/components/PageToggles.jsx](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/components/PageToggles.jsx)
- [x] [src/components/KeyScavenger.jsx](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/components/KeyScavenger.jsx)
- [x] [src/components/StatusBadge.jsx](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/components/StatusBadge.jsx)
- [x] [src/styles/index.css](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/styles/index.css)
- [x] [includes/class-gswp-frontend.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-frontend.php)
- [x] [includes/class-gswp-verifier.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-verifier.php)
- [x] [includes/class-gswp-login.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-login.php)
- [x] [includes/class-gswp-assets.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-assets.php)
- [x] [includes/class-gswp-xootix.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-xootix.php)
- [x] [includes/class-gswp-powerpack.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-powerpack.php)
- [x] [includes/class-gswp-conflict-guard.php](file:///Users/rwaterbury/Developer/google-security-for-wordpress/includes/class-gswp-conflict-guard.php)
- [x] [src/components/Compatibility.jsx](file:///Users/rwaterbury/Developer/google-security-for-wordpress/src/components/Compatibility.jsx)
- [x] [readme.txt](file:///Users/rwaterbury/Developer/google-security-for-wordpress/readme.txt)
- [x] [STATE.md](file:///Users/rwaterbury/Developer/google-security-for-wordpress/STATE.md)

### Current Status
- Assets successfully built.
- Manual scan integration for Smart Key Scavenger successfully completed and linted.
- Ready to compile final ZIP plugin package for distribution.
- Ready to push code to GitHub.
