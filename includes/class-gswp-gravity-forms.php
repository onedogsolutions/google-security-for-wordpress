<?php
/**
 * Gravity Forms Detection Utility
 *
 * Provides static helpers to detect when Gravity Forms has its own reCAPTCHA
 * Enterprise integration active on the current page. When GF handles reCAPTCHA
 * natively, this plugin defers entirely: no script loading, no Conflict Guard
 * suppression, and no server-side token validation for GF form submissions.
 *
 * All methods are static; no instantiation is required.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Gravity_Forms {

	/**
	 * Cached result of should_defer() for the current request.
	 *
	 * @var bool|null
	 */
	private static $defer_cache = null;

	/**
	 * Whether Gravity Forms is active and has a reCAPTCHA site key configured.
	 *
	 * GF stores its reCAPTCHA add-on settings in the
	 * 'gravityformsaddon_recaptcha_settings' option. A non-empty site_key
	 * indicates GF will load its own reCAPTCHA script on form pages.
	 *
	 * @return bool True when GF is present with reCAPTCHA configured.
	 */
	public static function is_recaptcha_configured() {
		if ( ! class_exists( 'GFCommon' ) && ! defined( 'GF_VERSION' ) ) {
			return false;
		}

		$settings = get_option( 'gravityformsaddon_recaptcha_settings', array() );

		return ! empty( $settings['site_key'] );
	}

	/**
	 * Whether the current page renders a Gravity Form.
	 *
	 * Checks (in order of reliability):
	 * 1. Whether GF's frontend scripts are enqueued (most accurate at render time).
	 * 2. Whether the global $post contains a GF shortcode or block.
	 *
	 * @return bool True when a Gravity Form is present on this page.
	 */
	public static function is_form_rendered() {
		// Late check: GF enqueues these handles when rendering a form.
		if ( wp_script_is( 'gform_gravityforms', 'enqueued' )
			|| wp_script_is( 'gform_recaptcha_v3', 'enqueued' )
			|| wp_script_is( 'gforms_recaptcha_frontend', 'enqueued' )
			|| wp_script_is( 'gforms_recaptcha_recaptcha', 'enqueued' ) ) {
			return true;
		}

		// Fallback: inspect the current post for a GF shortcode or block.
		global $post;
		if ( $post instanceof WP_Post ) {
			if ( has_shortcode( $post->post_content, 'gravityform' )
				|| has_shortcode( $post->post_content, 'gravityforms' )
				|| has_block( 'gravityforms/form', $post ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Master check: should this plugin defer to Gravity Forms on this page?
	 *
	 * Returns true only when GF has reCAPTCHA configured AND a form is being
	 * rendered on the current page. The result is cached per-request so
	 * repeated calls (Conflict Guard, Frontend, Assets) are inexpensive.
	 *
	 * @return bool True when our plugin should step aside.
	 */
	public static function should_defer() {
		if ( null === self::$defer_cache ) {
			self::$defer_cache = self::is_recaptcha_configured() && self::is_form_rendered();
		}

		return self::$defer_cache;
	}

	/**
	 * Whether the current request is a Gravity Forms form submission.
	 *
	 * Used server-side to skip our reCAPTCHA token validation when GF handles
	 * its own verification. GF includes a 'gform_submit' POST field with the
	 * form ID on every submission.
	 *
	 * @return bool True when this POST is a GF submission.
	 */
	public static function is_form_submission() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- GF validates its own nonce before our hook fires.
		return isset( $_POST['gform_submit'] );
	}
}
