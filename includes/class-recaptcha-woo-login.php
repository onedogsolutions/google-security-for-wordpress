<?php
/**
 * WordPress Core Login Class
 *
 * Adds reCAPTCHA v3 scoring to the WordPress core authentication screens
 * served by wp-login.php: sign in, user registration, and lost password.
 * These screens are independent of WooCommerce, so this works on any
 * WordPress install.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Login {

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

		if ( '1' === get_option( 'recaptcha_woo_enable_wp_login', '0' ) ) {
			add_action( 'login_form', array( $this, 'inject_login_field' ) );
			// Priority 30 runs after the core username/password checks so the
			// reCAPTCHA result layers on top of normal authentication.
			add_filter( 'authenticate', array( $this, 'validate_login' ), 30, 3 );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_wp_register', '0' ) ) {
			add_action( 'register_form', array( $this, 'inject_register_field' ) );
			add_filter( 'registration_errors', array( $this, 'validate_register' ), 10, 3 );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_wp_lostpassword', '0' ) ) {
			add_action( 'lostpassword_form', array( $this, 'inject_lostpassword_field' ) );
			add_action( 'lostpassword_post', array( $this, 'validate_lostpassword' ), 10, 1 );
		}

		// Print the Google API script and bootstrap on wp-login.php when at
		// least one screen is protected.
		if ( $this->is_any_enabled() ) {
			add_action( 'login_footer', array( $this, 'print_scripts' ) );
		}
	}

	/**
	 * Whether any of the core auth screens are protected.
	 *
	 * @return bool True when at least one screen is enabled.
	 */
	private function is_any_enabled() {
		return '1' === get_option( 'recaptcha_woo_enable_wp_login', '0' )
			|| '1' === get_option( 'recaptcha_woo_enable_wp_register', '0' )
			|| '1' === get_option( 'recaptcha_woo_enable_wp_lostpassword', '0' );
	}

	/**
	 * Inject the hidden field into the sign in form.
	 */
	public function inject_login_field() {
		$this->inject_field( 'login' );
	}

	/**
	 * Inject the hidden field into the registration form.
	 */
	public function inject_register_field() {
		$this->inject_field( 'register' );
	}

	/**
	 * Inject the hidden field into the lost password form.
	 */
	public function inject_lostpassword_field() {
		$this->inject_field( 'lostpassword' );
	}

	/**
	 * Print the hidden reCAPTCHA response field carrying its action.
	 *
	 * @param string $action The reCAPTCHA action name for this form.
	 */
	private function inject_field( $action ) {
		$site_key = get_option( 'recaptcha_woo_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);
	}

	/**
	 * Validate the wp-login.php sign in attempt.
	 *
	 * @param null|WP_User|WP_Error $user     Authenticated user or error so far.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return null|WP_User|WP_Error Original value on success, WP_Error to block.
	 */
	public function validate_login( $user, $username, $password ) {
		// Only enforce on the core login form submission. The `authenticate`
		// filter also fires for programmatic auth (XML-RPC, application
		// passwords) which never carry our token; gating on the core form
		// fields avoids blocking those flows.
		if ( ! $this->is_core_login_post() ) {
			return $user;
		}

		$result = $this->verifier->verify_token( 'wp_login', 'login' );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return $user;
	}

	/**
	 * Validate the wp-login.php registration attempt.
	 *
	 * @param WP_Error $errors         Current registration errors.
	 * @param string   $sanitized_user Sanitized login (unused).
	 * @param string   $user_email     Submitted email (unused).
	 * @return WP_Error Filtered registration errors.
	 */
	public function validate_register( $errors, $sanitized_user = '', $user_email = '' ) {
		$result = $this->verifier->verify_token( 'wp_register', 'register' );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $errors ) ) {
				$errors = new WP_Error();
			}
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $errors;
	}

	/**
	 * Validate the wp-login.php lost password attempt.
	 *
	 * @param WP_Error $errors Lost password errors object.
	 */
	public function validate_lostpassword( $errors ) {
		$result = $this->verifier->verify_token( 'wp_lostpassword', 'lostpassword' );
		if ( is_wp_error( $result ) && is_wp_error( $errors ) ) {
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}
	}

	/**
	 * Detect a genuine wp-login.php sign in submission.
	 *
	 * @return bool True when the core login form was posted.
	 */
	private function is_core_login_post() {
		if ( ! isset( $GLOBALS['pagenow'] ) || 'wp-login.php' !== $GLOBALS['pagenow'] ) {
			return false;
		}

		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			return false;
		}

		// The core login form posts the `log` (username) field.
		return isset( $_POST['log'] );
	}

	/**
	 * Print the Google reCAPTCHA script and token bootstrap in the login footer.
	 *
	 * wp-login.php does not run the standard wp_enqueue_scripts pipeline, so
	 * the tags are emitted directly. The bootstrap fetches a fresh token at
	 * submit time for each protected form, keeping single-use tokens valid no
	 * matter how long the screen sits open.
	 */
	public function print_scripts() {
		$site_key = get_option( 'recaptcha_woo_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		$is_enterprise = 'enterprise' === get_option( 'recaptcha_woo_key_type', 'classic' );
		$script_base   = $is_enterprise
			? 'https://www.google.com/recaptcha/enterprise.js'
			: 'https://www.google.com/recaptcha/api.js';
		$script_url    = $script_base . '?render=' . rawurlencode( $site_key );

		printf(
			'<script src="%s"></script>',
			esc_url( $script_url )
		);

		printf(
			'<script>%s</script>',
			$this->get_inline_js( $site_key, $is_enterprise ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON-encoded values, no HTML.
		);
	}

	/**
	 * Build the inline bootstrap JavaScript for the core login screens.
	 *
	 * @param string $site_key      The reCAPTCHA site key.
	 * @param bool   $is_enterprise Whether the Enterprise API is in use.
	 * @return string Inline JavaScript.
	 */
	private function get_inline_js( $site_key, $is_enterprise ) {
		ob_start();
		?>
		(function() {
			'use strict';

			if (window.recaptchaWooLoginInit) {
				return;
			}
			window.recaptchaWooLoginInit = true;

			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;
			var isEnterprise = <?php echo $is_enterprise ? 'true' : 'false'; ?>;

			function api() {
				if (typeof grecaptcha === 'undefined') {
					return null;
				}
				return isEnterprise ? grecaptcha.enterprise : grecaptcha;
			}

			function fetchToken(input) {
				return new Promise(function(resolve, reject) {
					var client = api();

					if (!client || !input) {
						reject();
						return;
					}

					client.ready(function() {
						var action = input.getAttribute('data-recaptcha-action') || 'submit';
						client.execute(siteKey, { action: action }).then(
							function(token) {
								input.value = token;
								resolve(token);
							},
							reject
						);
					});
				});
			}

			function noop() {}

			function refreshAll() {
				var inputs = document.querySelectorAll('.g-recaptcha-response');
				for (var i = 0; i < inputs.length; i++) {
					fetchToken(inputs[i]).catch(noop);
				}
			}

			function init() {
				// Pre-fetch so a token is present even before interaction.
				refreshAll();

				var forms = document.querySelectorAll('#loginform, #registerform, #lostpasswordform');
				for (var i = 0; i < forms.length; i++) {
					forms[i].addEventListener('submit', function(e) {
						var form = e.target;
						var input = form.querySelector('.g-recaptcha-response');

						// Already refreshed for this submit, or nothing to do.
						if (!input || !api() || form.getAttribute('data-recaptcha-ready') === '1') {
							return;
						}

						// Fetch a fresh, single-use token then resubmit.
						e.preventDefault();
						var submit = function() {
							form.setAttribute('data-recaptcha-ready', '1');
							form.submit();
						};
						fetchToken(input).then(submit, submit);
					});
				}
			}

			if ('loading' === document.readyState) {
				document.addEventListener('DOMContentLoaded', init);
			} else {
				init();
			}
		})();
		<?php
		return ob_get_clean();
	}
}
