<?php
/**
 * WordPress Core Login Class
 *
 * Adds reCAPTCHA v3 scoring to the WordPress core authentication screens
 * served by wp-login.php: sign in, user registration, and lost password.
 * These screens are independent of WooCommerce, so this works on any
 * WordPress install.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Login {

	/**
	 * Shared verifier used to score submitted tokens.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Assessment name captured for the password-reset form submission this
	 * request, carried from validate_password_reset() to after_password_reset().
	 *
	 * @var string
	 */
	private $reset_assessment_name = '';

	/**
	 * Constructor.
	 *
	 * @param GSWP_Verifier $verifier Token verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		if ( '1' === get_option( 'gswp_enable_wp_login', '0' ) ) {
			add_action( 'login_form', array( $this, 'inject_login_field' ) );
			// Priority 30 runs after the core username/password checks so the
			// reCAPTCHA result layers on top of normal authentication.
			add_filter( 'authenticate', array( $this, 'validate_login' ), 30, 3 );
		}

		if ( '1' === get_option( 'gswp_enable_wp_register', '0' ) ) {
			add_action( 'register_form', array( $this, 'inject_register_field' ) );
			add_filter( 'registration_errors', array( $this, 'validate_register' ), 10, 3 );
		}

		if ( '1' === get_option( 'gswp_enable_wp_lostpassword', '0' ) ) {
			add_action( 'lostpassword_form', array( $this, 'inject_lostpassword_field' ) );
			// Two args: the second is the requested WP_User, used as the Account
			// Defender identifier and to store a pending assessment for the reset.
			add_action( 'lostpassword_post', array( $this, 'validate_lostpassword' ), 10, 2 );
		}

		// Account Defender: assess and annotate the password-reset completion so
		// the takeover model sees a credential change confirmed by email control.
		// This runs on wp-login.php?action=rp regardless of the lost-password
		// scoring toggle, since the reset form is the second half of that flow.
		if ( $this->reset_events_active() ) {
			add_action( 'resetpass_form', array( $this, 'inject_resetpass_field' ) );
			add_action( 'validate_password_reset', array( $this, 'validate_password_reset' ), 10, 2 );
			add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
		}

		// Print the Google API script and bootstrap on wp-login.php when at
		// least one screen is protected (including the password-reset form).
		if ( $this->is_any_enabled() || $this->reset_events_active() ) {
			add_action( 'login_footer', array( $this, 'print_scripts' ) );
		}
	}

	/**
	 * Whether Account Defender account-modification events are active.
	 *
	 * @return bool
	 */
	private function reset_events_active() {
		return class_exists( 'GSWP_Account_Defender' ) && GSWP_Account_Defender::events_active();
	}

	/**
	 * Whether any of the core auth screens are protected.
	 *
	 * @return bool True when at least one screen is enabled.
	 */
	private function is_any_enabled() {
		return '1' === get_option( 'gswp_enable_wp_login', '0' )
			|| '1' === get_option( 'gswp_enable_wp_register', '0' )
			|| '1' === get_option( 'gswp_enable_wp_lostpassword', '0' );
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
		// Single gate shared with server-side enforcement: never print a token
		// field this plugin cannot populate.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);

		// The `login_form` / `register_form` / `lostpassword_form` actions also
		// fire on front-end forms rendered by other plugins (e.g. the PowerPack
		// Login Form module). There the wp-login.php footer script path never
		// runs, so load the shared API script and token bootstrap here to keep
		// the field populated.
		if ( ! $this->is_wp_login_page() ) {
			GSWP_Assets::enqueue_api_script();
			GSWP_Assets::add_refresh_bootstrap();
		}
	}

	/**
	 * Whether the current request is the core wp-login.php screen.
	 *
	 * @return bool True on wp-login.php.
	 */
	private function is_wp_login_page() {
		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'];
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

		// At priority 30 the core password check (priority 20) has already run,
		// so $user is the resolved WP_User on a correct password; otherwise fall
		// back to the submitted login name for the Account Defender identifier.
		$identifier = ( $user instanceof WP_User )
			? $user
			: ( isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		$result = $this->verifier->verify_token( 'wp_login', 'login', array(), $identifier );
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
		$result = $this->verifier->verify_token( 'wp_register', 'register', array(), $user_email );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $errors ) ) {
				$errors = new WP_Error();
			}
			$errors->add( 'recaptcha_error', $result->get_error_message() );
			return $errors;
		}

		// The score passed; also consult any Account Defender fake-signup labels.
		$screen = GSWP_Account_Defender::screen_registration( $this->verifier, (string) $user_email, 'wp-login' );
		if ( is_wp_error( $screen ) ) {
			if ( ! is_wp_error( $errors ) ) {
				$errors = new WP_Error();
			}
			$errors->add( 'recaptcha_error', $screen->get_error_message() );
		}

		// Local content heuristic: catch gibberish field data even when Google
		// returns no Account Defender labels. Core's form only has user_login
		// and user_email, but themes/plugins may add name/website fields.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core validates the registration nonce before this filter.
		$content_fields = array(
			'first_name' => isset( $_POST['first_name'] ) ? sanitize_text_field( wp_unslash( $_POST['first_name'] ) ) : '',
			'last_name'  => isset( $_POST['last_name'] ) ? sanitize_text_field( wp_unslash( $_POST['last_name'] ) ) : '',
			'user_url'   => isset( $_POST['user_url'] ) ? sanitize_text_field( wp_unslash( $_POST['user_url'] ) ) : '',
		);
		$content_screen = GSWP_Account_Defender::screen_registration_content( $content_fields, (string) $user_email, 'wp-login' );
		if ( is_wp_error( $content_screen ) ) {
			if ( ! is_wp_error( $errors ) ) {
				$errors = new WP_Error();
			}
			$errors->add( 'recaptcha_error', $content_screen->get_error_message() );
		}

		return $errors;
	}

	/**
	 * Validate the wp-login.php lost password attempt.
	 *
	 * @param WP_Error           $errors    Lost password errors object.
	 * @param WP_User|false|null $user_data The user the reset was requested for.
	 */
	public function validate_lostpassword( $errors, $user_data = null ) {
		// Attach the Account Defender identifier when the requested account is
		// known, so the lost-password assessment carries the same accountId as
		// the eventual reset completion.
		$identifier = $user_data instanceof WP_User ? $user_data : null;

		$result = $this->verifier->verify_token( 'wp_lostpassword', 'lostpassword', array(), $identifier );
		if ( is_wp_error( $result ) && is_wp_error( $errors ) ) {
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		// Account Defender: evaluate risk labels on the reset request.
		if ( class_exists( 'GSWP_Account_Defender' ) ) {
			$screen = GSWP_Account_Defender::screen_lost_password( $this->verifier, $user_data, 'wp-login' );
			if ( is_wp_error( $screen ) && is_wp_error( $errors ) ) {
				$errors->add( 'recaptcha_error', $screen->get_error_message() );
			}
		}

		// Remember this assessment so completing the reset (a later request that
		// carries no token) can annotate it once email control is proven.
		if ( $user_data instanceof WP_User && $this->reset_events_active() ) {
			$name = $this->verifier->get_last_assessment_name();
			if ( '' !== $name ) {
				GSWP_Account_Defender::store_pending(
					'lostpw_' . $user_data->ID,
					$name,
					(int) apply_filters( 'password_reset_expiration', DAY_IN_SECONDS )
				);
			}
		}
	}

	/**
	 * Inject the hidden field into the password-reset form (action=rp).
	 */
	public function inject_resetpass_field() {
		$site_key = get_option( 'gswp_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( 'password_reset' )
		);
	}

	/**
	 * Assess the password-reset submission (never blocks).
	 *
	 * validate_password_reset also fires when the reset form is first rendered
	 * (a GET with no pass1), so only the actual submission is assessed. The
	 * outcome is annotated by on_password_reset() once the change is committed.
	 *
	 * @param WP_Error         $errors Reset errors object (left untouched).
	 * @param WP_User|WP_Error $user   The user resetting their password.
	 */
	public function validate_password_reset( $errors, $user = null ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core validates the reset key before this hook.
		if ( ! isset( $_POST['pass1'] ) ) {
			return; // Form render, not a submission.
		}
		if ( ! $user instanceof WP_User ) {
			return;
		}

		// Account changes are recorded, not blocked: ignore the result so a low
		// score can never stop a legitimate password reset.
		$this->verifier->verify_token( 'password_reset', 'password_reset', array(), $user );
		$this->reset_assessment_name = $this->verifier->get_last_assessment_name();
	}

	/**
	 * Annotate the completed password reset as legitimate.
	 *
	 * Annotates the reset-form assessment and, when the reset began from a lost-
	 * password request, the stored assessment for that request too.
	 *
	 * @param WP_User $user     The user whose password was reset.
	 * @param string  $new_pass The new password (unused).
	 */
	public function on_password_reset( $user, $new_pass = '' ) {
		if ( ! class_exists( 'GSWP_Account_Defender' ) || ! GSWP_Account_Defender::events_active() ) {
			return;
		}

		if ( '' !== $this->reset_assessment_name ) {
			GSWP_Account_Defender::annotate( $this->reset_assessment_name, 'LEGITIMATE' );
		}

		if ( $user instanceof WP_User ) {
			$pending = GSWP_Account_Defender::take_pending( 'lostpw_' . $user->ID );
			if ( '' !== $pending ) {
				GSWP_Account_Defender::annotate( $pending, 'LEGITIMATE' );
			}
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
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		$site_key = GSWP_Recaptcha_Loader::site_key();

		$is_enterprise = 'enterprise' === get_option( 'gswp_key_type', 'classic' );
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

			if (window.gswpLoginInit) {
				return;
			}
			window.gswpLoginInit = true;

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

				var forms = document.querySelectorAll('#loginform, #registerform, #lostpasswordform, #resetpassform');
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
