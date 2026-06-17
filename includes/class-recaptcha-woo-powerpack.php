<?php
/**
 * PowerPack for Beaver Builder Login Form Integration
 *
 * Adds reCAPTCHA v3 scoring to the login and lost password forms rendered by
 * the PowerPack "Login Form" module (bb-powerpack).
 *
 * The module's forms fire the WordPress core `login_form` and
 * `lostpassword_form` actions, so the hidden token field is injected by
 * Recaptcha_Woo_Login. The module then serializes the whole form with FormData
 * before submitting over admin-ajax, so the token reaches the server. This
 * class validates that token:
 *
 *  - Login uses the module's own `pp_login_form_process_login_errors` filter,
 *    which runs before wp_signon() and surfaces errors in the module UI.
 *  - Lost password has no such filter, so its admin-ajax action is guarded at
 *    an early priority instead.
 *
 * These forms reuse the WordPress core toggles, thresholds, and verifier.
 * PowerPack supports classic v3 keys only, so configure a classic key type.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Powerpack {

	/**
	 * Shared verifier used to score submitted tokens.
	 *
	 * @var Recaptcha_Woo_Verifier
	 */
	private $verifier;

	/**
	 * Constructor.
	 *
	 * @param Recaptcha_Woo_Verifier $verifier Token verifier instance.
	 */
	public function __construct( Recaptcha_Woo_Verifier $verifier ) {
		$this->verifier = $verifier;

		// PowerPack for Beaver Builder must be active.
		if ( ! class_exists( 'BB_PowerPack' ) ) {
			return;
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_wp_login', '0' ) ) {
			add_filter( 'pp_login_form_process_login_errors', array( $this, 'validate_login' ), 10, 3 );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_wp_lostpassword', '0' ) ) {
			// The lost password handler exposes no validation filter, so guard
			// its admin-ajax action before the module processes it (its handler
			// runs at the default priority of 10).
			add_action( 'wp_ajax_pp_lf_process_lost_pass', array( $this, 'guard_lostpassword' ), 1 );
			add_action( 'wp_ajax_nopriv_pp_lf_process_lost_pass', array( $this, 'guard_lostpassword' ), 1 );
		}
	}

	/**
	 * Validate a PowerPack login submission.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param string   $user_login       Submitted username (unused).
	 * @param string   $user_password    Submitted password (unused).
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_login( $validation_error, $user_login = '', $user_password = '' ) {
		if ( ! is_wp_error( $validation_error ) ) {
			$validation_error = new WP_Error();
		}

		$result = $this->verifier->verify_token( 'wp_login', 'login' );
		if ( is_wp_error( $result ) ) {
			$validation_error->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_error;
	}

	/**
	 * Guard the PowerPack lost password admin-ajax action.
	 *
	 * Runs before the module's own handler; on a failed score it ends the
	 * request with a JSON error the module renders inline.
	 */
	public function guard_lostpassword() {
		$result = $this->verifier->verify_token( 'wp_lostpassword', 'lostpassword' );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}
	}
}
