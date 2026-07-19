<?php
/**
 * PowerPack for Beaver Builder Integration
 *
 * Adds reCAPTCHA v3 scoring to the login and lost password forms rendered by
 * the PowerPack "Login Form" module and to the "Registration Form" module
 * (bb-powerpack). Each module serializes its whole form with FormData before
 * submitting over admin-ajax, so an injected hidden token field reaches the
 * server. This class validates that token, integrating with each module the
 * cleanest way it exposes:
 *
 *  - Login form: fires the WordPress core `login_form` action (so GSWP_Login
 *    injects the field) and validates through the module's own
 *    `pp_login_form_process_login_errors` filter before wp_signon().
 *  - Lost password: no validation filter, so its admin-ajax action is guarded
 *    at an early priority instead.
 *  - Registration form: fires neither core register hook. Its own
 *    `pp_rf_form_end` action (inside the <form>) injects the field, and its
 *    `pp_rf_before_user_register` action — which fires after the module's nonce
 *    and field validation and immediately before wp_insert_user() — validates
 *    the score, so no user is created on a failed check.
 *
 * When the matching form is protected, the module's own reCAPTCHA is stripped
 * so this plugin's single, site-wide reCAPTCHA is the only one on the form.
 *
 * These forms reuse the WordPress core toggles, thresholds, and verifier.
 * PowerPack supports classic v3 keys only for its *own* captcha, but this
 * plugin's scoring is key-type agnostic (it loads enterprise.js for Enterprise
 * keys), so either key type works for the token this class injects.
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

		$login_on    = '1' === get_option( 'gswp_enable_wp_login', '0' );
		$register_on = '1' === get_option( 'gswp_enable_wp_register', '0' );

		if ( $login_on ) {
			add_filter( 'pp_login_form_process_login_errors', array( $this, 'validate_login' ), 10, 3 );
		}

		if ( $register_on ) {
			// The Registration Form module fires its own actions rather than the
			// core register_form / registration_errors hooks: inject the token
			// field inside the form, then validate the score immediately before
			// the user is created.
			add_action( 'pp_rf_form_end', array( $this, 'inject_registration_field' ) );
			add_action( 'pp_rf_before_user_register', array( $this, 'validate_registration' ), 10, 2 );
		}

		// Prefer this plugin's single, site-wide reCAPTCHA over each module's
		// own: strip the module's reCAPTCHA so only our token field remains and
		// our score is the one generated for the form. Registered once for both
		// modules; replace_module_recaptcha() gates per module by the matching
		// form toggle.
		if ( $login_on || $register_on ) {
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
	 * Inject the hidden reCAPTCHA response field into the Registration Form.
	 *
	 * Hooked to the module's own `pp_rf_form_end` action, which fires inside the
	 * <form> just before it closes, so the field is serialized with the module's
	 * FormData submission and posted to admin-ajax. Also loads the shared API
	 * script and token bootstrap so the field carries a fresh token at submit
	 * time. Inert when no site key is configured.
	 *
	 * @param object|null $settings The module settings (unused).
	 */
	public function inject_registration_field( $settings = null ) {
		if ( empty( GSWP_Assets::site_key() ) ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( 'register' )
		);

		if ( GSWP_Assets::enqueue_api_script() ) {
			GSWP_Assets::add_refresh_bootstrap();
		}
	}

	/**
	 * Validate a Registration Form submission before the user is created.
	 *
	 * Hooked to the module's `pp_rf_before_user_register` action, which fires
	 * after the module's nonce and field validation and immediately before
	 * wp_insert_user(). On a failed score the request is ended with the module's
	 * JSON error shape, so no user row is created and the module renders the
	 * message inline (an unknown error code falls through to our message). The
	 * submitted email seeds the Account Defender identifier.
	 *
	 * @param array       $userdata The submitted, sanitized form data.
	 * @param object|null $settings The module settings (unused).
	 */
	public function validate_registration( $userdata, $settings = null ) {
		$email = ( is_array( $userdata ) && ! empty( $userdata['user_email'] ) ) ? $userdata['user_email'] : null;

		$result = $this->verifier->verify_token( 'wp_register', 'register', array(), $email );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'code'    => 'gswp_recaptcha',
					'message' => $result->get_error_message(),
				)
			);
		}
	}

	/**
	 * Remove a PowerPack module's own reCAPTCHA / hCaptcha field.
	 *
	 * Handles both the Login Form and Registration Form modules. When this
	 * plugin protects the corresponding form, its hidden token field is already
	 * injected and submitted with the module's FormData. Leaving the module's
	 * own captcha in place would load a second reCAPTCHA and, worse, once its
	 * loader is suppressed (the Conflict Guard suppresses the `g-recaptcha`
	 * handle) the module's client-side gating would block the form for everyone.
	 * Stripping the captcha field makes the module skip it entirely — client
	 * side (no `.pp-grecaptcha` element to execute) and server side (no captcha
	 * flag posted) — so this plugin's site-wide score is the only one generated.
	 *
	 * @param string $content The rendered module HTML.
	 * @param object $module  The Beaver Builder module instance.
	 * @return string Filtered module HTML.
	 */
	public function replace_module_recaptcha( $content, $module ) {
		if ( ! is_object( $module ) ) {
			return $content;
		}

		$class = get_class( $module );

		if ( 'PPLoginFormModule' === $class && '1' === get_option( 'gswp_enable_wp_login', '0' ) ) {
			// Drop the module's captcha field wrappers (single level of nesting).
			$stripped = preg_replace(
				'~<div class="pp-login-form-field pp-field-group pp-field-type-(?:re|h)captcha">.*?</div>\s*</div>~s',
				'',
				$content
			);
		} elseif ( 'PPRegistrationFormModule' === $class && '1' === get_option( 'gswp_enable_wp_register', '0' ) ) {
			// The Registration Form module renders its captcha inside a field
			// wrapper flagged with data-field-type="recaptcha" that closes after
			// the error <span>.
			$stripped = preg_replace(
				'~<div class="pp-rf-field[^"]*" data-field-type="recaptcha">.*?</span>\s*</div>~s',
				'',
				$content
			);
		} else {
			return $content;
		}

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

		$identifier = '' !== $user_login ? $user_login : null;
		$result     = $this->verifier->verify_token( 'wp_login', 'login', array(), $identifier );
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
