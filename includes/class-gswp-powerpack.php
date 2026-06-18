<?php
/**
 * PowerPack for Beaver Builder Login Form Integration
 *
 * Adds reCAPTCHA v3 scoring to the login and lost password forms rendered by
 * the PowerPack "Login Form" module (bb-powerpack).
 *
 * The module's forms fire the WordPress core `login_form` and
 * `lostpassword_form` actions, so the hidden token field is injected by
 * GSWP_Login. The module then serializes the whole form with FormData
 * before submitting over admin-ajax, so the token reaches the server. This
 * class validates that token:
 *
 *  - Login uses the module's own `pp_login_form_process_login_errors` filter,
 *    which runs before wp_signon() and surfaces errors in the module UI.
 *  - Lost password has no such filter, so its admin-ajax action is guarded at
 *    an early priority instead.
 *
 * When login protection is enabled, the module's own reCAPTCHA is stripped so
 * this plugin's single, site-wide reCAPTCHA is the only one on the form.
 *
 * These forms reuse the WordPress core toggles, thresholds, and verifier.
 * PowerPack supports classic v3 keys only, so configure a classic key type.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Powerpack {

	/**
	 * Shared verifier used to score submitted tokens.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Constructor.
	 *
	 * @param GSWP_Verifier $verifier Token verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		// PowerPack for Beaver Builder must be active.
		if ( ! class_exists( 'BB_PowerPack' ) ) {
			return;
		}

		if ( '1' === get_option( 'gswp_enable_wp_login', '0' ) ) {
			add_filter( 'pp_login_form_process_login_errors', array( $this, 'validate_login' ), 10, 3 );

			// Prefer this plugin's (site-wide) reCAPTCHA over the module's own:
			// strip the module's reCAPTCHA so only our token field remains and
			// our score is the one generated for the form.
			add_filter( 'fl_builder_render_module_content', array( $this, 'replace_module_recaptcha' ), 10, 2 );
		}

		if ( '1' === get_option( 'gswp_enable_wp_lostpassword', '0' ) ) {
			// The lost password handler exposes no validation filter, so guard
			// its admin-ajax action before the module processes it (its handler
			// runs at the default priority of 10).
			add_action( 'wp_ajax_pp_lf_process_lost_pass', array( $this, 'guard_lostpassword' ), 1 );
			add_action( 'wp_ajax_nopriv_pp_lf_process_lost_pass', array( $this, 'guard_lostpassword' ), 1 );
		}
	}

	/**
	 * Remove the PowerPack Login Form module's own reCAPTCHA / hCaptcha.
	 *
	 * When this plugin protects the login form, its hidden token field is
	 * already injected via the core `login_form` action and is submitted with
	 * the module's FormData. Leaving the module's own captcha in place would
	 * load a second reCAPTCHA (conflicting with ours) and fail validation once
	 * its loader is suppressed. Stripping the captcha field makes the module
	 * skip it entirely — client side (no `.pp-grecaptcha` element to execute)
	 * and server side (no `recaptcha` flag posted) — so this plugin's
	 * site-wide score is the only one generated.
	 *
	 * @param string $content The rendered module HTML.
	 * @param object $module  The Beaver Builder module instance.
	 * @return string Filtered module HTML.
	 */
	public function replace_module_recaptcha( $content, $module ) {
		if ( ! is_object( $module ) || 'PPLoginFormModule' !== get_class( $module ) ) {
			return $content;
		}

		// Drop the module's captcha field wrappers (single level of nesting).
		$stripped = preg_replace(
			'~<div class="pp-login-form-field pp-field-group pp-field-type-(?:re|h)captcha">.*?</div>\s*</div>~s',
			'',
			$content
		);

		if ( null !== $stripped ) {
			$content = $stripped;

			// The module still enqueues its captcha loader when enabled; remove
			// it so only this plugin's reCAPTCHA script runs on the page.
			wp_dequeue_script( 'g-recaptcha' );
			wp_dequeue_script( 'h-captcha' );
		}

		return $content;
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
