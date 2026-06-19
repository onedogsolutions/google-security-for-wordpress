<?php
/**
 * Login/Signup Popup (Xootix) Integration
 *
 * Adds reCAPTCHA v3 scoring to the AJAX login, registration, and lost password
 * forms rendered by the "Login/Signup Popup ( Inline Form + Woocommerce )"
 * plugin (slug: easy-login-woocommerce).
 *
 * The plugin exposes clean validation filters that run before it authenticates
 * the user, and a template action inside each form, so no request sniffing is
 * required. These forms reuse the WordPress core form toggles and thresholds.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Xootix {

	/**
	 * Shared verifier used to score submitted tokens.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Map of Xootix form slugs to this plugin's action name, enable option,
	 * and threshold context.
	 *
	 * @var array
	 */
	private $forms = array(
		'login'        => array(
			'action'  => 'login',
			'enable'  => 'gswp_enable_wp_login',
			'context' => 'wp_login',
		),
		'register'     => array(
			'action'  => 'register',
			'enable'  => 'gswp_enable_wp_register',
			'context' => 'wp_register',
		),
		'lostPassword' => array(
			'action'  => 'lostpassword',
			'enable'  => 'gswp_enable_wp_lostpassword',
			'context' => 'wp_lostpassword',
		),
	);

	/**
	 * Constructor.
	 *
	 * @param GSWP_Verifier $verifier Token verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		// The Login/Signup Popup plugin must be active.
		if ( ! function_exists( 'xoo_el' ) ) {
			return;
		}

		// Nothing to do unless at least one protected form is enabled.
		if ( ! $this->is_any_enabled() ) {
			return;
		}

		// Inject the hidden token field inside each rendered form.
		add_action( 'xoo_el_form_end', array( $this, 'inject_field' ), 10, 2 );

		// Validate before the plugin authenticates. These filters run inside
		// the plugin's admin-ajax handler, so they register in all contexts.
		if ( '1' === get_option( 'gswp_enable_wp_login', '0' ) ) {
			add_filter( 'xoo_el_process_login_errors', array( $this, 'validate_login' ), 10, 2 );
		}
		if ( '1' === get_option( 'gswp_enable_wp_register', '0' ) ) {
			add_filter( 'xoo_el_process_registration_errors', array( $this, 'validate_register' ), 10, 4 );
		}
		if ( '1' === get_option( 'gswp_enable_wp_lostpassword', '0' ) ) {
			add_filter( 'xoo_el_process_lostpw_errors', array( $this, 'validate_lostpassword' ), 10, 1 );
		}

		// The popup lives in the footer for logged-out visitors; load the API
		// script and token bootstrap so a fresh token is always present.
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ), 20 );
	}

	/**
	 * Whether any of the protected forms are enabled.
	 *
	 * @return bool True when at least one form is enabled.
	 */
	private function is_any_enabled() {
		foreach ( $this->forms as $form ) {
			if ( '1' === get_option( $form['enable'], '0' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Inject the hidden reCAPTCHA response field into a popup form.
	 *
	 * @param string $form The Xootix form slug ('login', 'register', 'lostPassword').
	 */
	public function inject_field( $form, $args = array() ) {
		if ( ! isset( $this->forms[ $form ] ) ) {
			return;
		}

		if ( '1' !== get_option( $this->forms[ $form ]['enable'], '0' ) ) {
			return;
		}

		if ( empty( GSWP_Assets::site_key() ) ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $this->forms[ $form ]['action'] )
		);
	}

	/**
	 * Validate a popup login submission.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param array    $creds            Submitted credentials (unused).
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_login( $validation_error, $creds = array() ) {
		$identifier = is_array( $creds ) && ! empty( $creds['user_login'] ) ? $creds['user_login'] : null;
		return $this->add_error( $validation_error, 'wp_login', 'login', $identifier );
	}

	/**
	 * Validate a popup registration submission.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param string   $username         Submitted username (unused).
	 * @param string   $password         Submitted password (unused).
	 * @param string   $email            Submitted email (unused).
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_register( $validation_error, $username = '', $password = '', $email = '' ) {
		return $this->add_error( $validation_error, 'wp_register', 'register', $email );
	}

	/**
	 * Validate a popup lost password submission.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_lostpassword( $validation_error ) {
		return $this->add_error( $validation_error, 'wp_lostpassword', 'lostpassword' );
	}

	/**
	 * Score the token and append any failure to the plugin's error object.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param string   $context          Threshold context.
	 * @param string   $action           Expected reCAPTCHA action.
	 * @param mixed    $identifier       Account identifier for Account Defender.
	 * @return WP_Error Filtered validation errors.
	 */
	private function add_error( $validation_error, $context, $action, $identifier = null ) {
		$result = $this->verifier->verify_token( $context, $action, array(), $identifier );

		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_error ) ) {
				$validation_error = new WP_Error();
			}
			$validation_error->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_error;
	}

	/**
	 * Load the reCAPTCHA API script and token bootstrap for the popup.
	 */
	public function enqueue_assets() {
		// The popup is only output for logged-out visitors.
		if ( is_user_logged_in() ) {
			return;
		}

		if ( GSWP_Assets::enqueue_api_script() ) {
			GSWP_Assets::add_refresh_bootstrap();
		}
	}
}
