=== Google reCAPTCHA v3 for WooCommerce ===
Contributors: One Dog Solutions
Tags: recaptcha, woocommerce, captcha, spam, security
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Google reCAPTCHA v3 scoring for the WordPress login, registration, and lost password screens plus the WooCommerce Login, Registration, and Checkout forms, with page-specific thresholds and automated key discovery. Works with or without WooCommerce.

== Description ==

Google reCAPTCHA v3 for WooCommerce provides a seamless, invisible security layer to protect your authentication and customer endpoints from automated abuse. Shield the WordPress login, registration, and lost password screens — and, when WooCommerce is active, the customer login, registration, and checkout flows — from carding, credentials brute-forcing, and spam accounts.

WooCommerce is optional: install the plugin on any WordPress site to protect the core wp-login.php screens. When WooCommerce is present, the additional store forms become available automatically.

= Features =
* **WordPress Core Screen Protection**: Scores the wp-login.php sign in, user registration, and lost password forms out of the box, with no WooCommerce required.
* **WooCommerce Support**: When WooCommerce is active, also protects the customer Login, Registration, and Checkout forms.
* **Complete Isolation**: Clean styling that matches modern admin dashboards without bleeding Tailwind resets into core WordPress screens.
* **Flexible Page-Specific Thresholds**: Configure custom score thresholds individually for every protected form.
* **Key Scavenging Onboarding**: Discovers existing reCAPTCHA keys registered by Gravity Forms, Fluent Forms, Beaver Builder, and PowerPack so you can import them with a single click.
* **Zero Overhead Frontend**: Only loads JavaScript on active target pages to maintain optimal client-side page speed.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/google-recaptcha-v3-for-woocommerce` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin.
3. Navigate to **Settings -> reCAPTCHA v3** to configure your site keys, protected forms, and score thresholds.

== Frequently Asked Questions ==

= Does this work with WooCommerce checkout blocks? =
Currently, this plugin supports the classic shortcode-based checkout pages.

= What score threshold should I use? =
We recommend a default threshold of 0.5. If you encounter spam submissions, increase the threshold closer to 1.0 (strict). If humans are blocked, lower it closer to 0.0 (lenient).

== Changelog ==

= 1.3.0 =
* Added reCAPTCHA v3 scoring to the WordPress core screens served by wp-login.php: sign in, user registration, and lost password, each with its own score threshold.
* Added integration with the Login/Signup Popup ( Inline Form + Woocommerce ) plugin (easy-login-woocommerce): its AJAX login, registration, and lost password forms are scored using the same WordPress form toggles and thresholds when that plugin is active.
* Added integration with the PowerPack for Beaver Builder Login Form module: its login and lost password forms are scored using the same WordPress form toggles and thresholds when PowerPack is active. PowerPack supports classic v3 keys only, so configure a classic key type when using it.
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
