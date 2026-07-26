<?php
/**
 * Frontend Class
 *
 * Handles public enqueuing of the Google reCAPTCHA scripts and form hidden inputs.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Frontend {

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Priority 20: run after other plugins have enqueued their scripts, so
		// the loader sees the full picture when deduplicating at render time.
		add_action( 'wp_enqueue_scripts', array( $this, 'register_scripts' ), 20 );

		// Check if forms are enabled and hook accordingly.
		if ( '1' === get_option( 'gswp_enable_login', '0' ) ) {
			add_action( 'woocommerce_login_form_end', array( $this, 'inject_login_field' ) );
		}

		if ( '1' === get_option( 'gswp_enable_registration', '0' ) ) {
			add_action( 'woocommerce_register_form_end', array( $this, 'inject_registration_field' ) );
		}

		if ( '1' === get_option( 'gswp_enable_checkout', '0' ) ) {
			add_action( 'woocommerce_review_order_before_submit', array( $this, 'inject_checkout_field' ) );
		}
	}

	/**
	 * Register the Google reCAPTCHA v3 script.
	 *
	 * Registration is owned by GSWP_Recaptcha_Loader, which also decides at
	 * render time whether our tag is emitted or deduplicated against another
	 * plugin's loader for the same site key.
	 */
	public function register_scripts() {
		GSWP_Recaptcha_Loader::ensure_registered();
	}

	/**
	 * Inject the hidden field for the login form.
	 */
	public function inject_login_field() {
		$this->inject_recaptcha_field( 'login' );
	}

	/**
	 * Inject the hidden field for the registration form.
	 */
	public function inject_registration_field() {
		$this->inject_recaptcha_field( 'register' );
	}

	/**
	 * Inject the hidden field for the checkout form.
	 */
	public function inject_checkout_field() {
		$this->inject_recaptcha_field( 'checkout' );
	}

	/**
	 * Inject hidden reCAPTCHA response fields into the form.
	 *
	 * @param string $action The reCAPTCHA action name for this form.
	 */
	public function inject_recaptcha_field( $action ) {
		// Single gate shared with server-side enforcement: never print a token
		// field this plugin cannot populate.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		// Ensure the API script is loaded and the shared bootstrap is queued.
		// The bootstrap prints once from the footer, so it is never duplicated
		// when WooCommerce re-renders this field inside AJAX checkout fragments.
		GSWP_Recaptcha_Loader::enqueue();

		// Print the hidden input field.
		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);
	}
}
