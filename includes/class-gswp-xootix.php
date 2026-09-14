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
 * The template action (`xoo_el_form_end`, fired inside each `<form>` by
 * templates/xoo-el-form.php) passes the form's *render slug*: the basename of
 * its section template, e.g. global/xoo-el-lostpw-section.php for the lost
 * password form. That slug is not the wire action — the lostpw section prints
 * `_xoo_el_form=lostPassword`, and that hidden input is what the AJAX handler
 * dispatches on. The two sides of this integration therefore key off different
 * identifiers: injection off the render slug below, validation off the wire
 * filters. Keying both off the wire action is how the lostpw form shipped with
 * no token field at all through v2.30.0 — the map carried 'lostPassword' where
 * the template action passes 'lostpw', so inject_field() printed nothing and
 * every popup reset failed with "Anti-spam verification token is missing".
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
	 * Map of Xootix form render slugs to this plugin's action name, enable
	 * option, and threshold context.
	 *
	 * Keys are the slugs `xoo_el_form_end` passes: the section template
	 * basenames in the plugin's templates/global/ directory ('login',
	 * 'register', 'lostpw'). The constructor adds 'lostPassword' — the wire
	 * action from the lostpw section's `_xoo_el_form` hidden input — as an
	 * alias, so a Xootix release that keys the section differently still
	 * injects. The action values are the reCAPTCHA action names, not slugs.
	 *
	 * @var array
	 */
	private $forms = array(
		'login'    => array(
			'action'  => 'login',
			'enable'  => 'gswp_enable_wp_login',
			'context' => 'wp_login',
		),
		'register' => array(
			'action'  => 'register',
			'enable'  => 'gswp_enable_wp_register',
			'context' => 'wp_register',
		),
		'lostpw'   => array(
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

		// Alias the lost-password wire action to the lostpw render slug. The
		// template action passes one slug per form render, so the alias can
		// never double-print; it only covers a Xootix release that keys the
		// section by the `_xoo_el_form` value instead of the template slug.
		$this->forms['lostPassword'] = $this->forms['lostpw'];

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
	 * @param string $form The Xootix form render slug ('login', 'register',
	 *                     'lostpw', or the 'lostPassword' wire-action alias).
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
		$had_error        = is_wp_error( $validation_error ) && $validation_error->has_errors();
		$validation_error = $this->add_error( $validation_error, 'wp_register', 'register', $email );

		// When the score passed, also consult any Account Defender fake-signup
		// labels for the assessment just made.
		if ( ! $had_error && ( ! is_wp_error( $validation_error ) || ! $validation_error->has_errors() ) ) {
			$screen = GSWP_Account_Defender::screen_registration( $this->verifier, (string) $email, 'xootix' );
			if ( is_wp_error( $screen ) ) {
				if ( ! is_wp_error( $validation_error ) ) {
					$validation_error = new WP_Error();
				}
				$validation_error->add( 'recaptcha_error', $screen->get_error_message() );
			}
		}

		// Local content heuristic: catch gibberish field data even when Google
		// returns no Account Defender labels.
		if ( ! $had_error && ( ! is_wp_error( $validation_error ) || ! $validation_error->has_errors() ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Xootix validates its own nonce before this filter.
			$content_fields = array(
				'first_name' => isset( $_POST['first_name'] ) ? sanitize_text_field( wp_unslash( $_POST['first_name'] ) ) : '',
				'last_name'  => isset( $_POST['last_name'] ) ? sanitize_text_field( wp_unslash( $_POST['last_name'] ) ) : '',
				'user_url'   => isset( $_POST['user_url'] ) ? sanitize_text_field( wp_unslash( $_POST['user_url'] ) ) : '',
			);
			$content_screen = GSWP_Account_Defender::screen_registration_content( $content_fields, (string) $email, 'xootix' );
			if ( is_wp_error( $content_screen ) ) {
				if ( ! is_wp_error( $validation_error ) ) {
					$validation_error = new WP_Error();
				}
				$validation_error->add( 'recaptcha_error', $content_screen->get_error_message() );
			}
		}

		return $validation_error;
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
