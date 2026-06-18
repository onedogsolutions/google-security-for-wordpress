<?php
/**
 * Plugin Name: Google Security for WordPress
 * Description: A Google-powered security suite for WordPress: reCAPTCHA v3 scoring on the WordPress and WooCommerce login, registration, lost password, and checkout forms, plus two-factor authentication (TOTP) compatible with Google Authenticator. Works with or without WooCommerce.
 * Version: 2.0.2
 * Author: One Dog Solutions
 * Author URI: https://onedog.solutions/
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Text Domain: google-security-for-wordpress
 * Domain Path: /languages
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

// Define plugin constants.
define( 'GSWP_VERSION', '2.0.2' );
define( 'GSWP_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'GSWP_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'GSWP_FILE', __FILE__ );

/**
 * Autoload classes or include them.
 */
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-assets.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-conflict-guard.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-verifier.php';
// The WordPress core login/registration/lost-password screens run outside the
// admin context (is_admin() is false on wp-login.php), so this class must load
// unconditionally for its hooks to fire.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-login.php';
// Third-party login plugins authenticate through admin-ajax (is_admin() is
// true there), so their integrations must also load unconditionally.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-xootix.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-powerpack.php';
// REST requests are not admin context (is_admin() is false for /wp-json),
// so the REST API class must load unconditionally for its routes to exist.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-rest-api.php';
// Two-factor authentication. The login challenge runs on wp-login.php (not an
// admin context) while enrollment runs in the profile screen, so the core class
// loads unconditionally.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-totp.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-two-factor.php';

if ( is_admin() ) {
	require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-admin.php';
} else {
	require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-frontend.php';
}

/**
 * Default option values, keyed by option name without the gswp_ prefix.
 *
 * Shared between activation and the legacy-settings migration so both stay in
 * sync.
 *
 * @return array<string,string> Map of option suffix => default value.
 */
function gswp_default_options() {
	return array(
		'site_key'                  => '',
		'secret_key'                => '',
		'key_type'                  => 'classic',
		'gcp_project_id'            => '',
		'gcp_api_key'               => '',
		'enable_login'              => '0',
		'enable_registration'       => '0',
		'enable_checkout'           => '0',
		'threshold_login'           => '0.5',
		'threshold_registration'    => '0.5',
		'threshold_checkout'        => '0.5',
		'enable_wp_login'           => '0',
		'enable_wp_register'        => '0',
		'enable_wp_lostpassword'    => '0',
		'threshold_wp_login'        => '0.5',
		'threshold_wp_register'     => '0.5',
		'threshold_wp_lostpassword' => '0.5',
		'conflict_mode'             => 'off',
		// Two-factor authentication.
		'2fa_enabled'               => '1',
		'2fa_enforced_roles'        => array(),
	);
}

/**
 * Activate the plugin.
 *
 * On activation we seed the default options, pull any credentials saved by the
 * predecessor "Google reCAPTCHA v3 for WooCommerce" plugin into the new option
 * keys, and then deactivate and delete that old plugin if it is still installed
 * so only this rebranded version remains.
 */
function gswp_activate() {
	foreach ( gswp_default_options() as $suffix => $default ) {
		add_option( 'gswp_' . $suffix, $default );
	}

	// Import keys/settings from the legacy plugin's options.
	gswp_import_legacy_options();

	// Remove the old plugin now that its settings have been carried over.
	gswp_remove_legacy_plugin();

	// Record the schema version so the migration routine is a no-op on fresh
	// installs.
	update_option( 'gswp_db_version', GSWP_VERSION );
}
register_activation_hook( __FILE__, 'gswp_activate' );

/**
 * Copy settings stored under the plugin's previous option prefix.
 *
 * Earlier releases (the "Google reCAPTCHA v3 for WooCommerce" plugin) stored
 * settings under the recaptcha_woo_ prefix. Copy any of those values over to the
 * new gswp_ prefix, so the install keeps its configuration after the rename,
 * then delete the legacy options so the database is left holding only the gswp_
 * keys.
 */
function gswp_import_legacy_options() {
	foreach ( gswp_default_options() as $suffix => $default ) {
		$new_key = 'gswp_' . $suffix;
		$old_key = 'recaptcha_woo_' . $suffix;

		$old_value = get_option( $old_key, null );
		if ( null !== $old_value ) {
			// Carry the legacy value over only when the new key is unset, then
			// remove the legacy option so no stale rows remain.
			if ( false === get_option( $new_key, false ) ) {
				update_option( $new_key, $old_value );
			}
			delete_option( $old_key );
		}

		// Ensure the new key exists with its default even when there was nothing
		// to migrate.
		add_option( $new_key, $default );
	}
}

/**
 * Deactivate and delete the predecessor reCAPTCHA v3 plugin if it is present.
 *
 * Matches the old plugin by its known file path, text domain, or plugin name so
 * a renamed install folder is still caught, while never touching this plugin's
 * own file.
 */
function gswp_remove_legacy_plugin() {
	if ( ! function_exists( 'get_plugins' ) || ! function_exists( 'deactivate_plugins' ) || ! function_exists( 'delete_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	// delete_plugins() relies on the filesystem abstraction.
	if ( ! function_exists( 'request_filesystem_credentials' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	$self            = plugin_basename( GSWP_FILE );
	$known_basename  = 'google-recaptcha-v3-for-woocommerce/google-recaptcha-v3-for-woocommerce.php';
	$legacy_plugins  = array();

	foreach ( get_plugins() as $basename => $data ) {
		if ( $basename === $self ) {
			continue;
		}

		$name   = isset( $data['Name'] ) ? $data['Name'] : '';
		$domain = isset( $data['TextDomain'] ) ? $data['TextDomain'] : '';

		if ( $basename === $known_basename
			|| 'google-recaptcha-v3-for-woocommerce' === $domain
			|| 'Google reCAPTCHA v3 for WooCommerce' === $name ) {
			$legacy_plugins[] = $basename;
		}
	}

	if ( empty( $legacy_plugins ) ) {
		return;
	}

	// Deactivate silently (skip the deactivation hooks of the old plugin) and
	// then delete its files.
	deactivate_plugins( $legacy_plugins, true );
	delete_plugins( $legacy_plugins );
}

/**
 * Migrate settings stored under the plugin's previous option prefix.
 *
 * Runs on every load as a safety net for upgrades that bypass the activation
 * hook, copying any lingering recaptcha_woo_ options into the gswp_ keys.
 */
function gswp_maybe_migrate() {
	if ( get_option( 'gswp_db_version' ) === GSWP_VERSION ) {
		return;
	}

	gswp_import_legacy_options();

	update_option( 'gswp_db_version', GSWP_VERSION );
}
add_action( 'plugins_loaded', 'gswp_maybe_migrate', 5 );

/**
 * Initialize the plugin classes.
 */
function gswp_init() {
	// Initialize validation/verification first.
	$verifier = new GSWP_Verifier();

	// Protect the WordPress core login, registration, and lost password
	// screens. Hooks only fire on wp-login.php, so this is inert elsewhere.
	new GSWP_Login( $verifier );

	// Extend the same protection to the Login/Signup Popup plugin's AJAX
	// forms. Inert unless that plugin is active.
	new GSWP_Xootix( $verifier );

	// Extend the same protection to the PowerPack (Beaver Builder) Login Form
	// module. Inert unless PowerPack is active.
	new GSWP_Powerpack( $verifier );

	// Suppress other plugins' reCAPTCHA scripts so this implementation is the
	// only one on the page. Inert unless a conflict mode is configured.
	new GSWP_Conflict_Guard();

	// Routes only register when rest_api_init fires, so this is a no-op
	// outside REST requests.
	new GSWP_Rest_Api();

	// Two-factor authentication (TOTP / Google Authenticator). Inert unless the
	// feature is enabled and a user has enrolled.
	new GSWP_Two_Factor();

	if ( is_admin() ) {
		new GSWP_Admin();
	} else {
		new GSWP_Frontend();
	}
}
add_action( 'plugins_loaded', 'gswp_init' );
