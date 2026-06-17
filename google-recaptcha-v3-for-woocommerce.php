<?php
/**
 * Plugin Name: Google reCAPTCHA v3 for WooCommerce
 * Description: Google reCAPTCHA v3 scoring for the WordPress login, registration, and lost password screens plus WooCommerce Login, Registration, and Checkout, with smart key scavenging. Works with or without WooCommerce.
 * Version: 1.3.0
 * Author: One Dog Solutions
 * Author URI: https://onedog.solutions/
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Text Domain: google-recaptcha-v3-for-woocommerce
 * Domain Path: /languages
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

// Define plugin constants.
define( 'RECAPTCHA_WOO_VERSION', '1.3.0' );
define( 'RECAPTCHA_WOO_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'RECAPTCHA_WOO_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'RECAPTCHA_WOO_FILE', __FILE__ );

/**
 * Autoload classes or include them.
 */
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-key-scavenger.php';
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-assets.php';
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-verifier.php';
// The WordPress core login/registration/lost-password screens run outside the
// admin context (is_admin() is false on wp-login.php), so this class must load
// unconditionally for its hooks to fire.
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-login.php';
// Third-party login plugins authenticate through admin-ajax (is_admin() is
// true there), so their integrations must also load unconditionally.
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-xootix.php';
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-powerpack.php';
// REST requests are not admin context (is_admin() is false for /wp-json),
// so the REST API class must load unconditionally for its routes to exist.
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-rest-api.php';

if ( is_admin() ) {
	require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-admin.php';
} else {
	require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-frontend.php';
}

/**
 * Activate the plugin.
 */
function recaptcha_woo_activate() {
	// Set default settings if not already set.
	add_option( 'recaptcha_woo_site_key', '' );
	add_option( 'recaptcha_woo_secret_key', '' );
	add_option( 'recaptcha_woo_key_type', 'classic' );
	add_option( 'recaptcha_woo_gcp_project_id', '' );
	add_option( 'recaptcha_woo_gcp_api_key', '' );
	add_option( 'recaptcha_woo_enable_login', '0' );
	add_option( 'recaptcha_woo_enable_registration', '0' );
	add_option( 'recaptcha_woo_enable_checkout', '0' );
	add_option( 'recaptcha_woo_threshold_login', '0.5' );
	add_option( 'recaptcha_woo_threshold_registration', '0.5' );
	add_option( 'recaptcha_woo_threshold_checkout', '0.5' );
	// WordPress core auth screens (wp-login.php, registration, lost password).
	add_option( 'recaptcha_woo_enable_wp_login', '0' );
	add_option( 'recaptcha_woo_enable_wp_register', '0' );
	add_option( 'recaptcha_woo_enable_wp_lostpassword', '0' );
	add_option( 'recaptcha_woo_threshold_wp_login', '0.5' );
	add_option( 'recaptcha_woo_threshold_wp_register', '0.5' );
	add_option( 'recaptcha_woo_threshold_wp_lostpassword', '0.5' );
}
register_activation_hook( __FILE__, 'recaptcha_woo_activate' );

/**
 * Initialize the plugin classes.
 */
function recaptcha_woo_init() {
	// Initialize validation/verification first.
	$verifier = new Recaptcha_Woo_Verifier();

	// Protect the WordPress core login, registration, and lost password
	// screens. Hooks only fire on wp-login.php, so this is inert elsewhere.
	new Recaptcha_Woo_Login( $verifier );

	// Extend the same protection to the Login/Signup Popup plugin's AJAX
	// forms. Inert unless that plugin is active.
	new Recaptcha_Woo_Xootix( $verifier );

	// Extend the same protection to the PowerPack (Beaver Builder) Login Form
	// module. Inert unless PowerPack is active.
	new Recaptcha_Woo_Powerpack( $verifier );

	// Routes only register when rest_api_init fires, so this is a no-op
	// outside REST requests.
	new Recaptcha_Woo_Rest_Api();

	if ( is_admin() ) {
		new Recaptcha_Woo_Admin();
	} else {
		new Recaptcha_Woo_Frontend();
	}
}
add_action( 'plugins_loaded', 'recaptcha_woo_init' );
