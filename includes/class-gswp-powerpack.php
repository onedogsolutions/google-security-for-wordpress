<?php
/**
 * PowerPack for Beaver Builder Integration
 *
 * Adds reCAPTCHA v3 scoring to the forms rendered by the PowerPack modules:
 * Login Form, Registration Form, Contact Form, and Subscribe Form
 * (bb-powerpack).
 *
 * The Login and Registration modules serialize their whole form with FormData
 * before submitting over admin-ajax, so an injected hidden token field reaches
 * the server automatically. This class validates that token, integrating with
 * each module the cleanest way it exposes:
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
 * The Contact Form and Subscribe Form modules build their AJAX payloads
 * manually in JavaScript ($.post() with a hand-constructed data object). A
 * hidden input injected into the form HTML is NOT included in the request
 * unless the client-side code is also patched. These two modules therefore
 * ship a small inline script that uses $.ajaxPrefilter to append the token to
 * the relevant AJAX actions at submit time — the same approach used by
 * GSWP_Beaver_Builder for the BB core modules.
 *
 * When the matching form is protected, the module's own reCAPTCHA is stripped
 * so this plugin's single, site-wide reCAPTCHA is the only one on the form.
 *
 * Login and Registration reuse the WordPress core toggles and thresholds.
 * Contact Form and Subscribe Form introduce new toggles (gswp_enable_pp_contact,
 * gswp_enable_pp_subscribe) and thresholds (gswp_threshold_pp_contact,
 * gswp_threshold_pp_subscribe) for contexts that have no existing equivalent.
 *
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
	 * Whether at least one protected Contact/Subscribe module was rendered this
	 * request, so the inline prefilter script should be emitted in the footer.
	 *
	 * @var bool
	 */
	private $needs_inline_js = false;

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

		$login_on     = '1' === get_option( 'gswp_enable_wp_login', '0' );
		$register_on  = '1' === get_option( 'gswp_enable_wp_register', '0' );
		$contact_on   = '1' === get_option( 'gswp_enable_pp_contact', '0' );
		$subscribe_on = '1' === get_option( 'gswp_enable_pp_subscribe', '0' );

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

		// --- Server-side guards for Contact/Subscribe (priority 1, before the
		// module's own handler at 10). ---

		if ( $contact_on ) {
			add_action( 'wp_ajax_pp_send_email', array( $this, 'guard_contact' ), 1 );
			add_action( 'wp_ajax_nopriv_pp_send_email', array( $this, 'guard_contact' ), 1 );
		}

		if ( $subscribe_on ) {
			add_action( 'wp_ajax_pp_subscribe_form_submit', array( $this, 'guard_subscribe' ), 1 );
			add_action( 'wp_ajax_nopriv_pp_subscribe_form_submit', array( $this, 'guard_subscribe' ), 1 );
		}

		// Prefer this plugin's single, site-wide reCAPTCHA over each module's
		// own: strip the module's reCAPTCHA so only our token field remains and
		// our score is the one generated for the form. Registered once for all
		// modules; replace_module_recaptcha() gates per module by the matching
		// form toggle.
		if ( $login_on || $register_on || $contact_on || $subscribe_on ) {
			add_filter( 'fl_builder_render_module_content', array( $this, 'replace_module_recaptcha' ), 10, 2 );
		}

		// Contact/Subscribe need the inline prefilter in the footer.
		// The Login Form's lost-password sub-form also submits over admin-ajax
		// and needs the token appended at send time, so include it here.
		if ( $contact_on || $subscribe_on || '1' === get_option( 'gswp_enable_wp_lostpassword', '0' ) ) {
			add_action( 'wp_footer', array( $this, 'print_inline_js' ), 25 );
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
		// Single gate shared with server-side enforcement: never print a token
		// field this plugin cannot populate.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
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

		// The score passed; also consult any Account Defender fake-signup labels.
		$screen = GSWP_Account_Defender::screen_registration( $this->verifier, (string) $email, 'powerpack' );
		if ( is_wp_error( $screen ) ) {
			wp_send_json_error(
				array(
					'code'    => 'gswp_recaptcha',
					'message' => $screen->get_error_message(),
				)
			);
		}

		// Local content heuristic: catch gibberish field data even when Google
		// returns no Account Defender labels.
		$content_fields = array(
			'first_name' => is_array( $userdata ) && ! empty( $userdata['first_name'] ) ? $userdata['first_name'] : '',
			'last_name'  => is_array( $userdata ) && ! empty( $userdata['last_name'] ) ? $userdata['last_name'] : '',
			'user_url'   => is_array( $userdata ) && ! empty( $userdata['user_url'] ) ? $userdata['user_url'] : '',
		);
		$content_screen = GSWP_Account_Defender::screen_registration_content( $content_fields, (string) $email, 'powerpack' );
		if ( is_wp_error( $content_screen ) ) {
			wp_send_json_error(
				array(
					'code'    => 'gswp_recaptcha',
					'message' => $content_screen->get_error_message(),
				)
			);
		}
	}

	// ------------------------------------------------------------------
	// Server-side guards for Contact Form and Subscribe Form.
	// ------------------------------------------------------------------

	/**
	 * Guard the PowerPack Contact Form AJAX submission.
	 *
	 * Runs before the module's send_mail() handler (priority 1 vs 10). On a
	 * failed score the request is ended with the JSON shape the module's
	 * _submitComplete() reads: response.error (boolean) and response.message.
	 */
	public function guard_contact() {
		$result = $this->verifier->verify_token( 'pp_contact', 'contact' );
		if ( is_wp_error( $result ) ) {
			wp_send_json(
				array(
					'error'   => true,
					'message' => $result->get_error_message(),
				)
			);
		}
	}

	/**
	 * Guard the PowerPack Subscribe Form AJAX submission.
	 *
	 * Runs before the module's submit() handler (priority 1 vs 10). The module
	 * outputs raw JSON via echo json_encode(); die(); — NOT wp_send_json() —
	 * and its _submitFormComplete() parses data.error as a truthy string.
	 * This guard replicates that transport exactly.
	 */
	public function guard_subscribe() {
		$result = $this->verifier->verify_token( 'pp_subscribe', 'subscribe' );
		if ( is_wp_error( $result ) ) {
			echo wp_json_encode(
				array(
					'action'  => false,
					'error'   => $result->get_error_message(),
					'message' => false,
					'url'     => false,
				)
			);
			die();
		}
	}

	// ------------------------------------------------------------------
	// Front-end field injection and captcha stripping.
	// ------------------------------------------------------------------

	/**
	 * Remove a PowerPack module's own reCAPTCHA / hCaptcha / Turnstile field
	 * and inject this plugin's hidden token field where needed.
	 *
	 * Handles the Login Form, Registration Form, Contact Form, and Subscribe
	 * Form modules. When this plugin protects the corresponding form, its
	 * hidden token field is injected and the module's own captcha is removed.
	 * Leaving the module's captcha in place would load a second reCAPTCHA and,
	 * worse, once its loader is suppressed (the Conflict Guard suppresses the
	 * `g-recaptcha` handle) the module's client-side gating would block the
	 * form for everyone. Stripping the captcha field makes the module skip it
	 * entirely — client side (no `.pp-grecaptcha` element to execute) and
	 * server side (no captcha flag posted) — so this plugin's site-wide score
	 * is the only one generated.
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

			// The lost-password sub-form submits via admin-ajax and needs the
			// inline prefilter to deliver a fresh token at send time.
			if ( '1' === get_option( 'gswp_enable_wp_lostpassword', '0' ) ) {
				$this->needs_inline_js = true;
			}
		} elseif ( 'PPRegistrationFormModule' === $class && '1' === get_option( 'gswp_enable_wp_register', '0' ) ) {
			// The Registration Form module renders its captcha inside a field
			// wrapper flagged with data-field-type="recaptcha" that closes after
			// the error <span>.
			$stripped = preg_replace(
				'~<div class="pp-rf-field[^"]*" data-field-type="recaptcha">.*?</span>\s*</div>~s',
				'',
				$content
			);
		} elseif ( 'PPContactFormModule' === $class && '1' === get_option( 'gswp_enable_pp_contact', '0' ) ) {
			$content  = $this->inject_token_field( $content, 'contact' );
			$stripped = $this->strip_contact_captcha( $content );
		} elseif ( 'PPSubscribeFormModule' === $class && '1' === get_option( 'gswp_enable_pp_subscribe', '0' ) ) {
			$content  = $this->inject_token_field_subscribe( $content, 'subscribe' );
			$stripped = $this->strip_subscribe_captcha( $content );
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

		// For Contact/Subscribe: request the shared API script, the token
		// bootstrap, and flag the inline prefilter for the footer.
		if ( 'PPContactFormModule' === $class || 'PPSubscribeFormModule' === $class ) {
			if ( GSWP_Assets::enqueue_api_script() ) {
				GSWP_Assets::add_refresh_bootstrap();
				$this->needs_inline_js = true;
			}
		}

		return $content;
	}

	/**
	 * Inject the hidden reCAPTCHA response field into the Contact Form HTML.
	 *
	 * The Contact Form uses a <form> element, so the field is placed just
	 * before the closing </form> tag.
	 *
	 * @param string $content Module HTML.
	 * @param string $action  reCAPTCHA action name for this form.
	 * @return string Modified HTML.
	 */
	private function inject_token_field( $content, $action ) {
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return $content;
		}

		$field = sprintf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);

		$pos = strrpos( $content, '</form>' );
		if ( false !== $pos ) {
			return substr_replace( $content, $field . "\n", $pos, 0 );
		}

		// Fallback: append at the end.
		return $content . "\n" . $field;
	}

	/**
	 * Inject the hidden reCAPTCHA response field into the Subscribe Form HTML.
	 *
	 * The Subscribe Form has NO <form> element — it is a <div class="pp-subscribe-form">.
	 * The field is placed just before the closing </div> of .pp-subscribe-form-inner
	 * (identified by the error message div that immediately precedes the button wrap).
	 * Fallback: insert before the button wrap div.
	 *
	 * @param string $content Module HTML.
	 * @param string $action  reCAPTCHA action name for this form.
	 * @return string Modified HTML.
	 */
	private function inject_token_field_subscribe( $content, $action ) {
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return $content;
		}

		$field = sprintf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);

		// Insert before the button wrap: <div class="pp-form-button pp-button-wrap"
		$pos = strpos( $content, '<div class="pp-form-button' );
		if ( false !== $pos ) {
			return substr_replace( $content, $field . "\n", $pos, 0 );
		}

		// Fallback: append at the end.
		return $content . "\n" . $field;
	}

	/**
	 * Strip the Contact Form module's own captcha fields (reCAPTCHA, hCaptcha,
	 * Turnstile).
	 *
	 * Each is rendered inside:
	 *   <div class="pp-input-group pp-recaptcha">...</div>
	 *   <div class="pp-input-group pp-hcaptcha">...</div>
	 *   <div class="pp-input-group pp-turnstile">...</div>
	 *
	 * @param string $content Module HTML.
	 * @return string|null Stripped HTML, or null if no regex matched.
	 */
	private function strip_contact_captcha( $content ) {
		$stripped = preg_replace(
			'~<div class="pp-input-group pp-(?:recaptcha|hcaptcha|turnstile)">.*?</div>\s*</div>~s',
			'',
			$content
		);

		return $stripped;
	}

	/**
	 * Strip the Subscribe Form module's own captcha fields (reCAPTCHA, hCaptcha).
	 *
	 * Each is rendered inside:
	 *   <div class="pp-form-field pp-recaptcha">...</div>
	 *   <div class="pp-form-field pp-hcaptcha">...</div>
	 *
	 * The inner structure has one nested div (the widget) plus a <p> error
	 * message, then the wrapper closes.
	 *
	 * @param string $content Module HTML.
	 * @return string|null Stripped HTML, or null if no regex matched.
	 */
	private function strip_subscribe_captcha( $content ) {
		$stripped = preg_replace(
			'~<div class="pp-form-field pp-(?:recaptcha|hcaptcha)">.*?</p>\s*</div>~s',
			'',
			$content
		);

		return $stripped;
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

	// ------------------------------------------------------------------
	// Client-side token delivery for Contact Form and Subscribe Form.
	// ------------------------------------------------------------------

	/**
	 * Print the inline prefilter script in the footer.
	 *
	 * The PowerPack Contact Form, Subscribe Form, and Login Form lost-password
	 * modules build their AJAX payloads manually — they do NOT serialize the
	 * form with FormData — so the hidden token field is not included in the
	 * $.post() data automatically. This script uses $.ajaxPrefilter to append
	 * the current token value to the relevant AJAX requests at send time.
	 *
	 * The shared GSWP bootstrap (printed by GSWP_Recaptcha_Loader) keeps the
	 * hidden field populated: it fetches on load, refreshes every 100 seconds,
	 * and refreshes on visibility change. The prefilter simply reads whatever
	 * value the field holds when the AJAX call is assembled.
	 *
	 * A capture-phase click handler also triggers a best-effort token refresh
	 * for PowerPack's <a>-tag buttons (the bootstrap's own click handler only
	 * targets button/input[type=submit] elements), and replaces the token after
	 * a failed submission so the next attempt carries a fresh one.
	 */
	public function print_inline_js() {
		if ( ! $this->needs_inline_js ) {
			return;
		}

		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		$actions = array();

		if ( '1' === get_option( 'gswp_enable_pp_contact', '0' ) ) {
			$actions[] = 'pp_send_email';
		}
		if ( '1' === get_option( 'gswp_enable_pp_subscribe', '0' ) ) {
			$actions[] = 'pp_subscribe_form_submit';
		}
		if ( '1' === get_option( 'gswp_enable_wp_lostpassword', '0' ) ) {
			$actions[] = 'pp_lf_process_lost_pass';
		}

		if ( empty( $actions ) ) {
			return;
		}

		$site_key      = GSWP_Recaptcha_Loader::site_key();
		$is_enterprise = GSWP_Recaptcha_Loader::is_enterprise();

		ob_start();
		?>
		(function($) {
			'use strict';

			if (window.gswpPPFormInit) {
				return;
			}
			window.gswpPPFormInit = true;

			var actions = <?php echo wp_json_encode( $actions ); ?>;
			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;
			var isEnterprise = <?php echo $is_enterprise ? 'true' : 'false'; ?>;

			function api() {
				if (typeof grecaptcha === 'undefined') {
					return null;
				}
				return isEnterprise ? grecaptcha.enterprise : grecaptcha;
			}

			function fetchToken(input) {
				var client = api();
				if (!client || !input) {
					return;
				}
				client.ready(function() {
					var action = input.getAttribute('data-recaptcha-action') || 'submit';
					client.execute(siteKey, { action: action }).then(function(token) {
						input.value = token;
					});
				});
			}

			// Append the current token to PowerPack module AJAX submissions.
			$.ajaxPrefilter(function(options) {
				if (!options.data || !options.type || options.type.toUpperCase() !== 'POST') {
					return;
				}

				var params;
				try {
					params = new URLSearchParams(options.data);
				} catch (e) {
					return;
				}

				var action = params.get('action');
				if (!action || actions.indexOf(action) === -1) {
					return;
				}

				// Already carries a token (future-proofing).
				if (params.has('g-recaptcha-response')) {
					return;
				}

				// Use the field matching this action so a page with both login
				// and lost-password forms does not send the wrong token.
				var input;
				if (action === 'pp_lf_process_lost_pass') {
					input = document.querySelector('.g-recaptcha-response[data-recaptcha-action="lostpassword"]');
				} else {
					input = document.querySelector('.g-recaptcha-response');
				}
				if (input && input.value) {
					options.data += '&g-recaptcha-response=' + encodeURIComponent(input.value);
				}
			});

			// Best-effort token refresh on PowerPack button click (capture phase,
			// before jQuery's bubble-phase handler builds the AJAX data).
			// The PowerPack modules use <a> tags as buttons, which the shared
			// bootstrap's click handler does not target.
			document.addEventListener('click', function(e) {
				var target = e.target;
				if (!target || !target.closest) {
					return;
				}

				var btn = target.closest('.pp-contact-form .pp-submit-button, .pp-subscribe-form .fl-button, .pp-login-form .pp-login-form-submit, .pp-login-form .pp-lf-submit, .pp-login-form input[type="submit"]');
				if (!btn) {
					return;
				}

				var form = btn.closest('form, .pp-contact-form, .pp-subscribe-form, .pp-login-form');
				if (!form) {
					return;
				}

				var input = form.querySelector('.g-recaptcha-response');
				if (input) {
					fetchToken(input);
				}
			}, true);

			// After a failed PowerPack AJAX submission, replace the spent token
			// so the next attempt carries a fresh one. Scoped to the protected
			// PowerPack actions to avoid interfering with other AJAX on the page.
			$(document).ajaxComplete(function(event, xhr, settings) {
				if (!settings.data) {
					return;
				}

				var params;
				try {
					params = new URLSearchParams(settings.data);
				} catch (e) {
					return;
				}

				var action = params.get('action');
				if (!action || actions.indexOf(action) === -1) {
					return;
				}

				var response;
				try {
					response = typeof xhr.responseJSON !== 'undefined'
						? xhr.responseJSON
						: JSON.parse(xhr.responseText);
				} catch (e) {
					return;
				}

				// Contact Form: error === true. Subscribe Form: error is truthy string.
				// Lost Password: wp_send_json_error() -> response.success === false.
				var failed = false;
				if (response) {
					if (action === 'pp_lf_process_lost_pass') {
						failed = (response.success === false);
					} else {
						failed = (response.error === true || (typeof response.error === 'string' && response.error !== '' && response.error !== '0'));
					}
				}
				if (failed) {
					var input;
					if (action === 'pp_lf_process_lost_pass') {
						input = document.querySelector('.g-recaptcha-response[data-recaptcha-action="lostpassword"]');
					} else {
						input = document.querySelector('.g-recaptcha-response');
					}
					if (input) {
						window.setTimeout(function() {
							fetchToken(input);
						}, 0);
					}
				}
			});
		})(jQuery);
		<?php
		$js = ob_get_clean();

		printf(
			'<script>%s</script>',
			$js // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON-encoded values and static JS, no user HTML.
		);
	}
}
