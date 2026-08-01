<?php
/**
 * Beaver Builder Core Module Integration
 *
 * Adds reCAPTCHA v3 scoring to the forms rendered by the Beaver Builder core
 * modules: Login Form (FLLoginFormModule), Contact Form (FLContactFormModule),
 * and Subscribe Form (FLSubscribeFormModule).
 *
 * Unlike the PowerPack modules — which serialize their whole form with FormData
 * so an injected hidden field reaches the server automatically — the BB core
 * modules build their AJAX payloads manually in JavaScript. A hidden input
 * injected into the form HTML is NOT included in the $.post() data unless the
 * client-side code is also patched. This class therefore ships a small inline
 * script that uses $.ajaxPrefilter to append the token to the relevant AJAX
 * actions at submit time.
 *
 * Server-side enforcement guards each module's admin-ajax action at priority 1,
 * before the module's own handler (priority 10). On a failed score the request
 * is ended with a JSON error in the shape the module's JavaScript expects, so
 * the error renders inline without a page reload.
 *
 * When a form is protected, the module's own reCAPTCHA (Contact Form and
 * Subscribe Form only) is stripped so this plugin's single, site-wide reCAPTCHA
 * is the only one on the page.
 *
 * These forms reuse the WordPress core toggles and thresholds where a matching
 * context exists (Login Form → gswp_enable_wp_login), and introduce new toggles
 * for contexts that have no existing equivalent (Contact Form, Subscribe Form).
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Beaver_Builder {

	/**
	 * Shared verifier used to score submitted tokens.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Whether at least one protected BB module was rendered this request, so
	 * the inline prefilter script should be emitted in the footer.
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

		// Beaver Builder must be active.
		if ( ! class_exists( 'FLBuilder' ) ) {
			return;
		}

		$login_on    = '1' === get_option( 'gswp_enable_wp_login', '0' );
		$contact_on  = '1' === get_option( 'gswp_enable_bb_contact', '0' );
		$subscribe_on = '1' === get_option( 'gswp_enable_bb_subscribe', '0' );

		// --- Server-side guards (priority 1, before the module's handler at 10). ---

		if ( $login_on ) {
			add_action( 'wp_ajax_nopriv_fl_builder_login_form_submit', array( $this, 'guard_login' ), 1 );
		}

		if ( $contact_on ) {
			add_action( 'wp_ajax_fl_builder_email', array( $this, 'guard_contact' ), 1 );
			add_action( 'wp_ajax_nopriv_fl_builder_email', array( $this, 'guard_contact' ), 1 );
		}

		if ( $subscribe_on ) {
			add_action( 'wp_ajax_fl_builder_subscribe_form_submit', array( $this, 'guard_subscribe' ), 1 );
			add_action( 'wp_ajax_nopriv_fl_builder_subscribe_form_submit', array( $this, 'guard_subscribe' ), 1 );
		}

		// --- Front-end field injection and module captcha stripping. ---

		if ( $login_on || $contact_on || $subscribe_on ) {
			add_filter( 'fl_builder_render_module_content', array( $this, 'filter_module_content' ), 10, 2 );
			add_action( 'wp_footer', array( $this, 'print_inline_js' ), 25 );
		}
	}

	// ------------------------------------------------------------------
	// Server-side guards.
	// ------------------------------------------------------------------

	/**
	 * Guard the BB Login Form AJAX submission.
	 *
	 * Runs before the module's handler calls wp_signon(). On a failed score
	 * the request is ended with a plain string error — the module's JS renders
	 * response.data as the inline error message.
	 *
	 * Account Defender needs no separate call here: when the score passes and
	 * the module proceeds to wp_signon(), the authenticate filter fires and
	 * GSWP_Account_Defender captures the assessment through its existing hook.
	 */
	public function guard_login() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the module verifies its own nonce at priority 10.
		$identifier = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : null;

		$result = $this->verifier->verify_token( 'wp_login', 'login', array(), $identifier );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}
	}

	/**
	 * Guard the BB Contact Form AJAX submission.
	 *
	 * The module's JS reads response.data.error (boolean) and
	 * response.data.message (string) on failure.
	 */
	public function guard_contact() {
		$result = $this->verifier->verify_token( 'bb_contact', 'contact' );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'error'   => true,
					'message' => $result->get_error_message(),
				)
			);
		}
	}

	/**
	 * Guard the BB Subscribe Form AJAX submission.
	 *
	 * The module's JS reads response.data.error (string) on failure.
	 */
	public function guard_subscribe() {
		$result = $this->verifier->verify_token( 'bb_subscribe', 'subscribe' );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'error' => $result->get_error_message(),
				)
			);
		}
	}

	// ------------------------------------------------------------------
	// Front-end field injection and module captcha stripping.
	// ------------------------------------------------------------------

	/**
	 * Inject the hidden reCAPTCHA token field and strip the module's own captcha.
	 *
	 * Hooked to `fl_builder_render_module_content`, which filters the rendered
	 * HTML of every BB module on the front end. For each protected module type:
	 *  - Injects a hidden g-recaptcha-response input (the shared bootstrap keeps
	 *    it populated with a fresh token).
	 *  - Strips the module's own reCAPTCHA markup and dequeues its loader script
	 *    so only this plugin's site-wide reCAPTCHA runs on the page.
	 *
	 * @param string $content The rendered module HTML.
	 * @param object $module  The Beaver Builder module instance.
	 * @return string Filtered module HTML.
	 */
	public function filter_module_content( $content, $module ) {
		if ( ! is_object( $module ) ) {
			return $content;
		}

		$class = get_class( $module );

		if ( 'FLLoginFormModule' === $class && '1' === get_option( 'gswp_enable_wp_login', '0' ) ) {
			$content = $this->inject_token_field( $content, 'login' );
			// The BB login form has no built-in reCAPTCHA to strip.
		} elseif ( 'FLContactFormModule' === $class && '1' === get_option( 'gswp_enable_bb_contact', '0' ) ) {
			$content = $this->inject_token_field( $content, 'contact' );
			$content = $this->strip_contact_recaptcha( $content );
		} elseif ( 'FLSubscribeFormModule' === $class && '1' === get_option( 'gswp_enable_bb_subscribe', '0' ) ) {
			$content = $this->inject_token_field( $content, 'subscribe' );
			$content = $this->strip_subscribe_recaptcha( $content );
		} else {
			return $content;
		}

		// At least one protected module rendered: request the shared API script,
		// the token bootstrap, and flag the inline prefilter for the footer.
		if ( GSWP_Assets::enqueue_api_script() ) {
			GSWP_Assets::add_refresh_bootstrap();
			$this->needs_inline_js = true;
		}

		return $content;
	}

	/**
	 * Inject the hidden reCAPTCHA response field into the module HTML.
	 *
	 * Placed just before the closing </form> tag (or the last </div> for the
	 * version-1 div-based layout) so it sits inside the form element.
	 *
	 * @param string $content Module HTML.
	 * @param string $action  reCAPTCHA action name for this form.
	 * @return string Modified HTML.
	 */
	private function inject_token_field( $content, $action ) {
		// Single gate shared with server-side enforcement: never print a token
		// field this plugin cannot populate.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return $content;
		}

		$field = sprintf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);

		// Insert before the closing </form> tag when present.
		$pos = strrpos( $content, '</form>' );
		if ( false !== $pos ) {
			return substr_replace( $content, $field . "\n", $pos, 0 );
		}

		// Version-1 modules use a <div role="form"> wrapper; append at the end.
		return $content . "\n" . $field;
	}

	/**
	 * Remove the Contact Form module's own reCAPTCHA field.
	 *
	 * The module renders its captcha inside:
	 *   <div class="fl-input-group fl-recaptcha">...</div>
	 * Stripping it prevents a second reCAPTCHA widget and the client-side
	 * gating that would block the form when no module-captcha response exists.
	 *
	 * @param string $content Module HTML.
	 * @return string Stripped HTML.
	 */
	private function strip_contact_recaptcha( $content ) {
		$stripped = preg_replace(
			'~<div class="fl-input-group fl-recaptcha">.*?</div>\s*</div>~s',
			'',
			$content
		);

		if ( null !== $stripped ) {
			$content = $stripped;
			wp_dequeue_script( 'g-recaptcha' );
		}

		return $content;
	}

	/**
	 * Remove the Subscribe Form module's own reCAPTCHA field.
	 *
	 * The module renders its captcha inside:
	 *   <div class="fl-form-field fl-form-recaptcha">...</div>
	 * in both the stacked and inline layout variants.
	 *
	 * @param string $content Module HTML.
	 * @return string Stripped HTML.
	 */
	private function strip_subscribe_recaptcha( $content ) {
		$stripped = preg_replace(
			'~<div class="fl-form-field fl-form-recaptcha">.*?</div>\s*</div>~s',
			'',
			$content
		);

		if ( null !== $stripped ) {
			$content = $stripped;
			wp_dequeue_script( 'g-recaptcha' );
		}

		return $content;
	}

	// ------------------------------------------------------------------
	// Client-side token delivery.
	// ------------------------------------------------------------------

	/**
	 * Print the inline prefilter script in the footer.
	 *
	 * The BB core modules build their AJAX payloads manually — they do NOT
	 * serialize the form with FormData — so the hidden token field is not
	 * included in the $.post() data automatically. This script uses
	 * $.ajaxPrefilter to append the current token value to the relevant AJAX
	 * requests at send time.
	 *
	 * The shared GSWP bootstrap (printed by GSWP_Recaptcha_Loader) keeps the
	 * hidden field populated: it fetches on load, refreshes every 100 seconds,
	 * and refreshes on visibility change. The prefilter simply reads whatever
	 * value the field holds when the AJAX call is assembled.
	 *
	 * A capture-phase click handler also triggers a best-effort token refresh
	 * for BB's <a>-tag buttons (the bootstrap's own click handler only targets
	 * button/input[type=submit] elements), and replaces the token after a
	 * failed submission so the next attempt carries a fresh one.
	 */
	public function print_inline_js() {
		if ( ! $this->needs_inline_js ) {
			return;
		}

		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		$actions = array();

		if ( '1' === get_option( 'gswp_enable_wp_login', '0' ) ) {
			$actions[] = 'fl_builder_login_form_submit';
		}
		if ( '1' === get_option( 'gswp_enable_bb_contact', '0' ) ) {
			$actions[] = 'fl_builder_email';
		}
		if ( '1' === get_option( 'gswp_enable_bb_subscribe', '0' ) ) {
			$actions[] = 'fl_builder_subscribe_form_submit';
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

			if (window.gswpBBInit) {
				return;
			}
			window.gswpBBInit = true;

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

			// Append the current token to BB module AJAX submissions.
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

				var input = document.querySelector('.g-recaptcha-response');
				if (input && input.value) {
					options.data += '&g-recaptcha-response=' + encodeURIComponent(input.value);
				}
			});

			// Best-effort token refresh on BB button click (capture phase,
			// before jQuery's bubble-phase handler builds the AJAX data).
			// The BB modules use <a> tags as buttons, which the shared
			// bootstrap's click handler does not target.
			document.addEventListener('click', function(e) {
				var target = e.target;
				if (!target || !target.closest) {
					return;
				}

				var btn = target.closest('.fl-login-form .fl-button, .fl-contact-form .fl-button, .fl-subscribe-form .fl-button');
				if (!btn) {
					return;
				}

				var form = btn.closest('form, [role="form"], .fl-login-form, .fl-contact-form, .fl-subscribe-form');
				if (!form) {
					return;
				}

				var input = form.querySelector('.g-recaptcha-response');
				if (input) {
					fetchToken(input);
				}
			}, true);

			// After a failed BB AJAX submission, replace the spent token so
			// the next attempt carries a fresh one. Scoped to the three BB
			// actions to avoid interfering with other AJAX on the page.
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
					response = xhr.responseJSON;
				} catch (e) {
					return;
				}

				// Only refresh on failure; a success may redirect away.
				if (response && response.success === false) {
					var input = document.querySelector('.g-recaptcha-response');
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
