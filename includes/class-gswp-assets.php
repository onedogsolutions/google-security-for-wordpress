<?php
/**
 * Shared Frontend Assets
 *
 * Centralizes loading of the Google reCAPTCHA API script and a generic token
 * refresh bootstrap so multiple integrations (WooCommerce, the Login/Signup
 * Popup plugin, Beaver Builder modules) can share one implementation.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Assets {

	/**
	 * Script handle for the Google reCAPTCHA API.
	 *
	 * Retained as an alias of GSWP_Recaptcha_Loader::HANDLE so existing callers
	 * (and the Conflict Guard) keep working.
	 */
	const HANDLE = GSWP_Recaptcha_Loader::HANDLE;

	/**
	 * Configured reCAPTCHA site key.
	 *
	 * @return string Site key, or empty string when unset.
	 */
	public static function site_key() {
		return GSWP_Recaptcha_Loader::site_key();
	}

	/**
	 * Whether the Enterprise key type is configured.
	 *
	 * @return bool True for Enterprise, false for classic v3.
	 */
	public static function is_enterprise() {
		return GSWP_Recaptcha_Loader::is_enterprise();
	}

	/**
	 * Register and enqueue the Google reCAPTCHA API script.
	 *
	 * Delegates to GSWP_Recaptcha_Loader, which owns registration and decides
	 * at render time whether our tag is emitted or deduplicated against another
	 * plugin's loader for the same site key.
	 *
	 * @return bool True when enqueued, false when no site key is configured.
	 */
	public static function enqueue_api_script() {
		return GSWP_Recaptcha_Loader::enqueue();
	}

	/**
	 * Request the shared token refresh bootstrap.
	 *
	 * The bootstrap is printed once from the footer by GSWP_Recaptcha_Loader
	 * rather than attached to our script handle, so it survives our loader tag
	 * being deduplicated away.
	 */
	public static function add_refresh_bootstrap() {
		GSWP_Recaptcha_Loader::request_bootstrap();
	}
}
