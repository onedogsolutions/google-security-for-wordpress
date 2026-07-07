=== Google Security for WordPress ===
Contributors: One Dog Solutions
Tags: recaptcha, woocommerce, two-factor, 2fa, security
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 2.8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A Google-powered security suite for WordPress: reCAPTCHA v3 scoring on the login, registration, lost password, and WooCommerce checkout forms, plus two-factor authentication (TOTP) compatible with Google Authenticator. Works with or without WooCommerce.

== Description ==

Google Security for WordPress bundles two complementary layers of protection for your site's accounts:

1. **Invisible bot scoring** with Google reCAPTCHA v3 on the WordPress login, registration, and lost password screens — and, when WooCommerce is active, the customer login, registration, and checkout flows — to stop carding, credential brute-forcing, and spam accounts.
2. **Two-factor authentication (2FA)** using time-based one-time passwords (TOTP), compatible with Google Authenticator, Authy, 1Password, and Microsoft Authenticator. No external service, account, or API is required — TOTP runs entirely on your site.

WooCommerce is optional: install the plugin on any WordPress site to protect the core wp-login.php screens and add 2FA. When WooCommerce is present, the additional store forms become available automatically.

= Features =
* **WordPress Core Screen Protection**: Scores the wp-login.php sign in, user registration, and lost password forms out of the box, with no WooCommerce required.
* **WooCommerce Support**: When WooCommerce is active, also protects the customer Login, Registration, and Checkout forms — including the modern WooCommerce Checkout block (Store API), so stores built on the block editor are covered by the same reCAPTCHA scoring and Transaction Defense as the classic checkout.
* **Transaction Defense (reCAPTCHA Enterprise)**: When using an Enterprise key, sends the order's billing/shipping address, amount, line items, and payment method with each checkout assessment to power Google's Fraud Prevention model, optionally blocks high-risk transactions, and annotates each order's outcome (legitimate/fraudulent) so the model keeps learning.
* **Account Defender (reCAPTCHA Enterprise)**: When using an Enterprise key, sends an anonymous, salted account identifier with each login, registration, and account-change assessment so Google's site-specific model can flag account takeovers, fake signups, and account farming. Logs the returned risk labels, optionally forces the two-factor challenge for enrolled users on suspicious logins, and annotates login, two-factor, and account-modification outcomes (correct/incorrect password, 2FA initiated/passed/failed, and legitimate password resets, email changes, and 2FA enable/disable) to train the model. Account changes are assessed, never blocked. Disabled by default.
* **Email Alerts**: Optionally email the site operator the moment Account Defender flags a suspicious login on an administrator account, or Transaction Defense blocks a high-risk checkout — events that otherwise only reach the log. Built-in throttling (per-event dedupe plus an hourly cap with digest overflow) keeps a brute-force run or checkout-bot from turning into inbox spam; choose immediate, hourly-digest, or daily-digest delivery. Disabled by default.
* **Two-Factor Authentication (Google Authenticator)**: Users enrol from their profile by scanning a QR code (or entering the setup key manually) and confirming a code. A second-factor challenge is then required at login.
* **Backup Codes**: Single-use recovery codes are generated at enrolment so users are never locked out if they lose their device.
* **Role-Based Enforcement**: Optionally require 2FA for selected roles (e.g. Administrators). Administrators can reset another user's 2FA from the user-edit screen.
* **Application-Password Hardening**: Optionally disable application passwords for users in a 2FA-enforced role, so a REST API or XML-RPC login can't bypass the second factor with a single credential. A per-account exemption list keeps deliberate integrations (e.g. an MCP server or backup tool on a dedicated service account) working. Off by default; fully reversible — turning it off restores existing application passwords without re-issuing them.
* **Flexible Page-Specific Thresholds**: Configure custom reCAPTCHA score thresholds individually for every protected form.
* **Seamless Upgrade**: On activation, automatically imports the site keys and settings from the predecessor "Google reCAPTCHA v3 for WooCommerce" plugin, then deactivates and removes that old plugin.
* **Zero Overhead Frontend**: Only loads JavaScript on active target pages to maintain optimal client-side page speed.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/google-security-for-wordpress` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin.
3. Navigate to **Settings -> Google Security** to configure your site keys, protected forms, and score thresholds.
4. Navigate to **Settings -> Two-Factor Auth** to enable two-factor authentication and (optionally) require it for specific roles.
5. Each user enables 2FA from **Users -> Profile -> Two-Factor Authentication**.

== Frequently Asked Questions ==

= Do I need a Google account or API for two-factor authentication? =
No. "Google Authenticator" support means the industry-standard TOTP algorithm (RFC 6238). The codes are generated and verified entirely on your own site, and any compatible app (Google Authenticator, Authy, 1Password, Microsoft Authenticator) will work.

= What happens if a user loses their phone? =
They can use one of the single-use backup codes shown when they enrolled. An administrator can also reset a user's 2FA from the user-edit screen to restore access.

= Does this work with WooCommerce checkout blocks? =
Yes. Both the classic shortcode-based checkout and the modern WooCommerce Checkout block (which submits over the Store API) are protected by the same reCAPTCHA scoring and, with an Enterprise key, the same Transaction Defense.

= What score threshold should I use? =
We recommend a default threshold of 0.5. If you encounter spam submissions, increase the threshold closer to 1.0 (strict). If humans are blocked, lower it closer to 0.0 (lenient).

= I enabled "Block application passwords for enforced roles" and my management tool lost connection. What now? =
Turning the block on immediately stops existing application passwords from working for users in an enforced role — including any that a site-management, backup, or automation tool (or an MCP server) uses to reach your site over the REST API. Before enabling the block, either move those integrations onto an account whose role is not enforced, or add the account's username to the **Exempt accounts** list under **Settings → Google Security → Two-Factor Authentication**. Exempted accounts keep application-password access (they still face the interactive two-factor challenge on normal logins). If you have already been locked out of the settings screen, sign in interactively with your password and second factor and either add the exemption or switch the block off — nothing is deleted, so your existing application passwords start working again the moment you do. Standard MainWP Child connections use their own secure key handshake rather than application passwords, so they are unaffected by this setting. For the recommended long-term setup, see "How do I set up a service account for REST integrations?" below.

= How do I set up a service account for REST integrations (MCP servers, backup and automation tools)? =
Point integrations at a dedicated machine account and exempt only that account, so your own administrator login keeps zero single-factor paths. The exemption is per-account, not per-password — exempting your personal admin account would re-open the whole application-password channel on it, including passwords that don't exist yet. A dedicated account also gives you clean revocation (delete one password or account without touching human access) and clean attribution (the integration's actions appear under its own name in logs and revisions).

1. **Create the account**: Users → Add New. Username like `mytool-svc`, an email alias you control, a generated password stored straight in your password manager (it is never typed again), role Administrator — or a trimmed custom role if the tool works with less.
2. **Optionally enrol it in 2FA**, storing the TOTP secret in your password manager. The account never logs in interactively, but enrolment also activates this plugin's XML-RPC password block for it, sealing that path too.
3. **Exempt it first**: Settings → Google Security → Two-Factor Authentication → Exempt accounts → add `mytool-svc`. Do this before creating the application password — once the block is on, the Application Passwords section is hidden for non-exempt accounts in enforced roles.
4. **Create the application password**: Users → edit `mytool-svc` → Application Passwords. Name it after the consuming tool (e.g. "Novamira – office LLM") so the "Last Used" column stays meaningful, and copy the one-time password into the integration's configuration.
5. **Enable the policy**: enforce the role, switch "Block application passwords for enforced roles" on, and make sure the Exempt accounts list contains only service accounts — no human logins.
6. **Cut over**: test the integration, then revoke any application passwords remaining on human accounts (Users → Profile → Application Passwords → Revoke).
7. **Operate**: one named application password per tool per site; review "Last Used" periodically; rotate on a schedule; on any incident, revoke that single password (or delete the service account) without disrupting anyone's normal access.

== Changelog ==

= 2.8.1 =
* The settings screen is now organised into tabs (API Credentials, Form Protection, Enterprise Defense, Two-Factor Auth, Alerts & Compatibility) so each section fits on screen instead of one long scroll. The active tab is reflected in the URL so it can be bookmarked or linked to directly, and no settings moved — everything still saves together with the one Save button.
* Fixed: the "Set up Two-Factor Authentication" button on the settings screen rendered its label in WordPress admin's link blue instead of white. A CSS cascade-layer conflict introduced by the Tailwind v4 upgrade caused WordPress admin's own link-colour rules to outrank the plugin's white-text style.

= 2.8.0 =
* Added an opt-in setting to disable application passwords for users in a 2FA-enforced role (Settings → Google Security → Two-Factor Authentication). Role-based enforcement only guaranteed a second factor on interactive logins; a REST API or XML-RPC login with an application password bypassed it by design. With this on, users in an enforced role can no longer create or authenticate with application passwords, so the "enforced accounts can't authenticate with a password alone" invariant finally holds. Existing application passwords are rejected while the block is on but not deleted, so switching it off restores them without re-issuing. A per-account exemption list keeps deliberate integrations working (point a REST integration such as an MCP server at a dedicated service account and exempt it — the account still gets the interactive two-factor challenge). Off by default; tied to the 2FA master switch.
* Fixed: XML-RPC password logins for enrolled users are now actually blocked. The block was written for the 2.0.0 release but its filter was never registered, so an enrolled account's password worked over XML-RPC with no second factor. It is now wired to the authentication flow as originally documented. (Application-password logins over XML-RPC are additionally covered by the new block above when it is enabled.)
* Documentation: corrected the WooCommerce checkout-block FAQ (the block-based checkout has been fully protected since 2.5.0) and added a step-by-step FAQ for setting up a dedicated service account for REST integrations such as MCP servers and backup tools.

= 2.7.0 =
* Added opt-in admin email alerts for the two security events that previously only reached the WooCommerce log: reCAPTCHA Enterprise Account Defender flagging a suspicious login (SUSPICIOUS_LOGIN_ACTIVITY) on an administrator-capable account, and Transaction Defense blocking a high-risk checkout (both the classic checkout and the WooCommerce Checkout block). Each alert email carries the relevant context — the account, roles, risk labels, IP and user agent for a flagged login; the risk score, billing details, cart total and checkout type for a blocked checkout. Throttling is built in so this can never become spam: repeats of the same event are de-duplicated within a window (an admin hammered by credential stuffing yields one email, not one per attempt), and a global hourly cap rolls any overflow into a single digest, so even a rotating-identity bot cannot flood the inbox. Delivery is configurable as immediate, hourly digest, or daily digest, sent to the site admin email or a custom comma-separated recipient list; emails are sent off the request's critical path so they never slow a login or checkout. Each event has its own on/off sub-toggle. Disabled by default; the two source features are reCAPTCHA Enterprise.

= 2.6.0 =
* Extended reCAPTCHA Enterprise Account Defender to account-modification events, completing the model's view of account takeover. In addition to logins and registrations, the plugin now assesses and annotates password resets (wp-login.php and WooCommerce), email-address changes, and two-factor enable/disable on the user profile and WooCommerce "Account details" screens — sending the same anonymous, salted account identifier and confirming each change as legitimate so Google's site-specific model learns what a real account owner's activity looks like, not just their sign-ins. Deferred flows (the password-reset email link and the profile email-confirmation link) are annotated when they complete, i.e. once control of the account's email is proven. Account changes are only assessed, never blocked. A new "Assess account changes" toggle under Account Defender (on by default) governs this; turning it off keeps login coverage without loading the reCAPTCHA script on the profile/account pages. Enterprise key type and Account Defender required.

= 2.5.0 =
* Added reCAPTCHA and Transaction Defense support for the modern WooCommerce Checkout block (Store API). Previously only the classic shortcode checkout was scored; stores using the block-based checkout received no reCAPTCHA verification and no Transaction Defense. The block now sends a fresh reCAPTCHA token with each checkout submission, which is scored server-side on the Store API checkout hook using the same thresholds, and Enterprise orders placed through the block are assessed and annotated (legitimate/fraudulent) exactly like classic-checkout orders. No configuration change is required — existing checkout settings apply automatically to both checkout types.

= 2.4.0 =
* Added a configurable grace period for role-enforced two-factor authentication (default 14 days, 0–30). Users in an enforced role who haven't set up 2FA now see a dashboard countdown notice with their deadline and a "Set up now" button instead of being locked out immediately; after the deadline, the dashboard redirects to their profile until 2FA is enabled. Each user's clock starts on their first dashboard visit while enforcement applies, so users added later get the same full window. Enrolling clears the clock, and an administrator 2FA reset grants a fresh window. Set the grace period to 0 for immediate enforcement (the previous behaviour).
* The settings screen now uses the standard WordPress admin background instead of its own tinted backdrop.

= 2.3.0 =
* Added a "Remember this browser for 30 days" option to two-factor authentication. When a user passes the 2FA code prompt they can trust the current browser, which then skips the code for 30 days. Trusted browsers are bound per-user, stored only as a salted HMAC (the cookie is HTTP-only, Secure, SameSite=Lax), capped per user, and automatically expire. A login that Account Defender flags as suspicious still requires the code even on a trusted browser. Users can forget all remembered browsers from their profile, disabling 2FA clears them, and a password reset revokes them. A new "Allow 'Remember this browser'" toggle (on by default) is available under Two-Factor Authentication.

= 2.2.2 =
* Hardened 2FA challenge modal focus. Replaced the single timeout with a robust requestAnimationFrame focus pattern that retries once if not immediately active, added autofocus and placeholder attributes to the authenticator code input, and ensured the input is refocused after validation errors.

= 2.2.1 =
* Reduced log volume. By default the plugin now logs only anomalies and failures to the WooCommerce log (source “gswp”): Account Defender records a login’s labels only when a genuine risk label is present (the benign PROFILE_MATCH returned on ordinary logins is no longer logged), and Transaction defense logs only when a checkout is actually blocked (the per-order risk is still saved as an order note). Added a “Verbose logging” toggle (off by default) under reCAPTCHA Conflict Handling to restore full per-assessment logging for debugging. WooCommerce already rotates these logs daily and prunes them after its retention period (30 days by default).

= 2.2.0 =
* Added reCAPTCHA Enterprise Account Defender. With an Enterprise key, the plugin sends an anonymous, salted account identifier (no email, username, or phone) with each login and registration assessment so Google can build its site-specific behavioural model, logs the returned risk labels (suspicious login activity, fake account creation, related-accounts-high, profile match), and annotates outcomes back to Google — correct/incorrect password on login plus two-factor initiated/passed/failed from the built-in 2FA flow. A new Account Defender settings panel adds an opt-in toggle to force the two-factor challenge for enrolled users on suspicious logins (others are logged only, never blocked). Disabled by default.

= 2.1.0 =
* Added reCAPTCHA Enterprise Transaction defense for WooCommerce checkout. The plugin now sends payment transaction data (billing/shipping address, amount, currency, line items, and payment method) with each Enterprise checkout assessment so Google returns a Fraud Prevention verdict, and annotates each order's outcome (completed = legitimate, refunded/cancelled/failed = fraudulent) to train the model. A new Transaction Defense settings panel adds an opt-in toggle to block high-risk transactions above a configurable risk threshold. Enterprise key type and WooCommerce required; disabled by default.

= 2.0.2 =
* Added an "Enable two-factor authentication" button directly beneath the authenticator setup field, so users no longer have to scroll to the bottom of the profile page to submit their first verification code. After submitting, the page returns to the authenticator section — where the one-time backup codes are shown — instead of jumping to the top of the page.

= 2.0.1 =
* Fixed the two-factor code-entry popup failing to open on AJAX logins (e.g. the Login/Signup Popup) on sites with a page cache or JavaScript optimiser such as FlyingPress, which could lock enrolled users out. The popup now opens by polling the server's held-login flag cookie, independent of any form submit event or deferred-script timing.

= 2.0.0 =
* Renamed the plugin from "Google reCAPTCHA v3 for WooCommerce" to "Google Security for WordPress" to reflect its broader scope. The settings menu is now **Settings -> Google Security**.
* On activation, the plugin now imports the site keys and settings from the old "Google reCAPTCHA v3 for WooCommerce" plugin, then deactivates and deletes that old plugin automatically.
* Added two-factor authentication (TOTP) compatible with Google Authenticator and other authenticator apps: per-user enrolment from the profile screen (QR code or manual setup key), a second-factor login challenge, single-use backup codes, and optional role-based enforcement.
* The settings screen now links directly to your profile for two-factor enrolment.
* Administrators can reset another user's two-factor authentication from the user-edit screen.
* XML-RPC logins are blocked for accounts with two-factor authentication enabled, closing a bypass of the second factor.
* Removed the experimental key-scavenging onboarding flow.

= 1.3.0 =
* Added reCAPTCHA v3 scoring to the WordPress core screens served by wp-login.php: sign in, user registration, and lost password, each with its own score threshold.
* Added integration with the Login/Signup Popup ( Inline Form + Woocommerce ) plugin (easy-login-woocommerce): its AJAX login, registration, and lost password forms are scored using the same WordPress form toggles and thresholds when that plugin is active.
* Added integration with the PowerPack for Beaver Builder Login Form module: its login and lost password forms are scored using the same WordPress form toggles and thresholds when PowerPack is active. PowerPack supports classic v3 keys only, so configure a classic key type when using it. When login protection is enabled, the module's own reCAPTCHA is removed so this plugin's single, site-wide reCAPTCHA is the only one on the form.
* Added reCAPTCHA conflict handling: optionally suppress reCAPTCHA scripts loaded by other plugins (such as Gravity Forms) so this plugin is the only reCAPTCHA on the page. Choose between disabled, only on pages where this plugin loads its own reCAPTCHA, or site-wide. Replaces hand-rolled wp_dequeue_script snippets and matches any Google reCAPTCHA loader by source.
* The plugin now works without WooCommerce. The WooCommerce login, registration, and checkout options only appear when WooCommerce is active.
* Moved the settings page out of the WooCommerce menu into Settings -> reCAPTCHA v3, and switched the required capability to manage_options.
* Removed the WooCommerce plugin dependency header so the plugin can be installed on any WordPress site.

= 1.2.2 =
* Fixed Gravity Forms key discovery: the reCAPTCHA Add-On stores v3 keys under site_key_v3/secret_key_v3, and the classic core implementation stores its v2 keys as standalone rg_gforms_captcha_* options. Both shapes are now detected; classic core keys are flagged as v2 and cannot be imported since this plugin requires v3 keys.

= 1.2.1 =
* Added "Requires at least" and "Requires PHP" headers to the main plugin file so WordPress displays version requirements during plugin upload and blocks installation on unsupported environments.

= 1.2.0 =
* Fixed Fluent Forms key detection in the Smart Key Scavenger: keys are now read from the _fluentform_reCaptcha_details option that Fluent Forms actually uses (legacy global settings shapes are still checked as a fallback).
* The scavenger now detects the reCAPTCHA version of Fluent Forms keys and blocks importing v2 (checkbox) keys, which are incompatible with this v3 plugin.
* The key scan now lists every discovered configuration (e.g. both Gravity Forms and Fluent Forms) instead of only the first match, with per-source import buttons.

= 1.1.1 =
* Fixed "No route was found matching the URL and request method" when saving settings: the REST API routes were only registered in admin context, but /wp-json requests are not admin context, so the settings endpoints never existed. Routes now register on all requests.

= 1.1.0 =
* Tokens are now fetched on page load and refreshed automatically before expiry (and on checkout updates/errors), so checkout submissions triggered by payment gateway scripts (Stripe, PayPal smart buttons, express checkout) always carry a valid token. Fixes "Anti-spam verification token is missing" errors.
* The frontend bootstrap is now dependency-free vanilla JavaScript, so performance plugins that delay or defer jQuery cannot delay token generation. Checkout fragment updates and error notices are detected via MutationObserver, with jQuery checkout events used as a progressive enhancement when available.
* Added reCAPTCHA Enterprise support: select the Enterprise key type and verify tokens through the reCAPTCHA Enterprise assessments API using a Google Cloud project ID and API key.
* Credential misconfiguration (invalid secret key, bad API key/project) is now logged to WooCommerce > Status > Logs and no longer blocks customers from checking out.

= 1.0.0 =
* Initial release.
