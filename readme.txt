=== Google Security for WordPress ===
Contributors: One Dog Solutions
Tags: recaptcha, woocommerce, two-factor, 2fa, security
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 2.0.0
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
* **WooCommerce Support**: When WooCommerce is active, also protects the customer Login, Registration, and Checkout forms.
* **Two-Factor Authentication (Google Authenticator)**: Users enrol from their profile by scanning a QR code (or entering the setup key manually) and confirming a code. A second-factor challenge is then required at login.
* **Backup Codes**: Single-use recovery codes are generated at enrolment so users are never locked out if they lose their device.
* **Role-Based Enforcement**: Optionally require 2FA for selected roles (e.g. Administrators). Administrators can reset another user's 2FA from the user-edit screen.
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
Currently, this plugin supports the classic shortcode-based checkout pages.

= What score threshold should I use? =
We recommend a default threshold of 0.5. If you encounter spam submissions, increase the threshold closer to 1.0 (strict). If humans are blocked, lower it closer to 0.0 (lenient).

== Changelog ==

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
