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
	 * GF script handles that must never be suppressed when GF has reCAPTCHA.
	 *
	 * @var string[]
	 */
	private static $gf_handles = array(
		'gform_gravityforms',
		'gform_recaptcha',
		'gform_recaptcha_v3',
		'gforms_recaptcha_frontend',
		'gforms_recaptcha_recaptcha',
	);

	/**
	 * Whether Gravity Forms is active.
	 *
	 * Simple presence check — does not require reCAPTCHA to be configured.
	 * Used by the Conflict Guard as a broad safety gate: when GF is active,
	 * reCAPTCHA suppression is disabled because GF may load its own reCAPTCHA
	 * on any page with a form and we cannot reliably detect which pages those
	 * are due to script-enqueue timing differences across GF versions.
	 *
	 * @return bool True when Gravity Forms is installed and active.
	 */
	public static function is_active() {
		return defined( 'GF_VERSION' ) || class_exists( 'GFForms' ) || class_exists( 'GFCommon' );
	}

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

		// GF may store the key as 'site_key' or 'public_key' depending on version.
		return ! empty( $settings['site_key'] ) || ! empty( $settings['public_key'] );
	}

	/**
	 * Whether the current page renders a Gravity Form.
	 *
	 * Checks (in order of reliability):
	 * 1. Whether GF's frontend scripts are enqueued or registered.
	 * 2. Whether the global $post contains a GF shortcode, block, or form markup.
	 *
	 * @return bool True when a Gravity Form is present on this page.
	 */
	public static function is_form_rendered() {
		// Check both 'enqueued' and 'registered' — GF may register early but
		// enqueue late, or vice versa depending on version/rendering path.
		foreach ( self::$gf_handles as $handle ) {
			if ( wp_script_is( $handle, 'enqueued' ) || wp_script_is( $handle, 'registered' ) ) {
				return true;
			}
		}

		// Also check the main GF script that loads on every page with a form.
		if ( wp_script_is( 'gform_gravityforms', 'enqueued' )
			|| wp_script_is( 'gform_gravityforms', 'registered' )
			|| wp_script_is( 'gravityforms', 'enqueued' )
			|| wp_script_is( 'gravityforms', 'registered' ) ) {
			return true;
		}

		// Fallback: inspect the current post for a GF shortcode, block, or
		// rendered form markup (covers template-embedded and widget forms).
		global $post;
		if ( $post instanceof WP_Post ) {
			if ( has_shortcode( $post->post_content, 'gravityform' )
				|| has_shortcode( $post->post_content, 'gravityforms' )
				|| has_block( 'gravityforms/form', $post )
				|| false !== strpos( $post->post_content, 'gform_wrapper' )
				|| false !== strpos( $post->post_content, 'gf-form' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Master check: should this plugin defer to Gravity Forms on this page?
	 *
	 * Returns true when GF has reCAPTCHA configured AND a form is being
	 * rendered on the current page. NOT cached: the result can change from
	 * false to true as GF enqueues scripts later in the page lifecycle.
	 *
	 * @return bool True when our plugin should step aside.
	 */
	public static function should_defer() {
		return self::is_recaptcha_configured() && self::is_form_rendered();
	}

	/**
	 * Whether a script handle belongs to Gravity Forms.
	 *
	 * Used by the Conflict Guard to whitelist GF handles when GF has
	 * reCAPTCHA configured — regardless of whether a form is confirmed
	 * on the current page (GF only loads reCAPTCHA on form pages).
	 *
	 * @param string $handle The script handle to check.
	 * @return bool True when the handle is a known GF script.
	 */
	public static function is_gf_handle( $handle ) {
		return in_array( $handle, self::$gf_handles, true );
	}
}
