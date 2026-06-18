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
		add_action( 'wp_enqueue_scripts', array( $this, 'register_scripts' ) );

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
	 */
	public function register_scripts() {
		$site_key = get_option( 'gswp_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		// Enterprise site keys must load enterprise.js; classic v3 keys use api.js.
		$script_base = 'enterprise' === get_option( 'gswp_key_type', 'classic' )
			? 'https://www.google.com/recaptcha/enterprise.js'
			: 'https://www.google.com/recaptcha/api.js';

		// Register Google API script. No jQuery dependency: the inline
		// bootstrap is vanilla JS, so script optimizers that delay jQuery
		// cannot delay token generation.
		wp_register_script(
			'google-recaptcha-v3',
			$script_base . '?render=' . rawurlencode( $site_key ),
			array(),
			GSWP_VERSION,
			true
		);
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
		$site_key = get_option( 'gswp_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		// Ensure the API script is enqueued and our bootstrap is attached once.
		// The inline script rides on the main page footer, so it is never
		// duplicated when WooCommerce re-renders this field inside AJAX
		// checkout fragments.
		wp_enqueue_script( 'google-recaptcha-v3' );

		static $js_attached = false;
		if ( ! $js_attached ) {
			wp_add_inline_script( 'google-recaptcha-v3', $this->get_inline_js( $site_key ) );
			$js_attached = true;
		}

		// Print the hidden input field.
		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);
	}

	/**
	 * Build the inline JavaScript that keeps a fresh token in every field.
	 *
	 * Tokens are fetched proactively on page load and refreshed before the
	 * two-minute expiry, so submissions triggered by third-party scripts
	 * (Stripe, PayPal smart buttons, express checkout flows) always carry a
	 * valid token even when they bypass the standard submit events.
	 *
	 * Written in vanilla JS with no jQuery dependency so script optimizers
	 * that delay jQuery cannot delay token generation. Checkout fragment
	 * replacements and error notices are detected with a MutationObserver
	 * instead of WooCommerce's jQuery-only custom events; the jQuery event
	 * bindings are kept as a progressive enhancement when jQuery is present.
	 *
	 * @param string $site_key The reCAPTCHA site key.
	 * @return string Inline JavaScript.
	 */
	private function get_inline_js( $site_key ) {
		$is_enterprise = 'enterprise' === get_option( 'gswp_key_type', 'classic' );

		ob_start();
		?>
		(function() {
			'use strict';

			if (window.gswpInit) {
				return;
			}
			window.gswpInit = true;

			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;
			var isEnterprise = <?php echo $is_enterprise ? 'true' : 'false'; ?>;
			// reCAPTCHA v3 tokens expire after 120 seconds; refresh before that.
			var REFRESH_INTERVAL = 100 * 1000;

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

			// Coalesce bursts of DOM mutations into a single refresh.
			var refreshTimer = null;
			function queueRefresh() {
				if (refreshTimer) {
					return;
				}
				refreshTimer = setTimeout(function() {
					refreshTimer = null;
					refreshAll();
				}, 250);
			}

			function clearCheckoutTokens() {
				var inputs = document.querySelectorAll('form.woocommerce-checkout .g-recaptcha-response');
				for (var i = 0; i < inputs.length; i++) {
					inputs[i].value = '';
				}
			}

			function containsMatch(node, selector) {
				if (node.nodeType !== 1) {
					return false;
				}
				return node.matches(selector) || !!node.querySelector(selector);
			}

			function init() {
				refreshAll();

				setInterval(function() {
					if (!document.hidden) {
						refreshAll();
					}
				}, REFRESH_INTERVAL);

				// Tokens go stale while the tab is in the background.
				document.addEventListener('visibilitychange', function() {
					if (!document.hidden) {
						refreshAll();
					}
				});

				// WooCommerce replaces the payment fragment (and our hidden
				// input) whenever the order review updates, and inserts a
				// notice group when a checkout attempt fails. Tokens are
				// single use, so a failed attempt also needs a replacement.
				var observer = new MutationObserver(function(mutations) {
					for (var i = 0; i < mutations.length; i++) {
						var added = mutations[i].addedNodes;
						for (var j = 0; j < added.length; j++) {
							if (containsMatch(added[j], '.g-recaptcha-response')) {
								queueRefresh();
								return;
							}
							if (containsMatch(added[j], '.woocommerce-NoticeGroup-checkout, .woocommerce-error')) {
								clearCheckoutTokens();
								queueRefresh();
								return;
							}
						}
					}
				});
				observer.observe(document.body, { childList: true, subtree: true });

				// Fallback: intercept standard form submits (Login, Register)
				// if the token is somehow still missing. The native
				// form.submit() does not re-fire this listener.
				document.addEventListener('submit', function(e) {
					var form = e.target;
					if (!form.matches || !form.matches('form.login, form.register')) {
						return;
					}

					var input = form.querySelector('.g-recaptcha-response');
					if (input && !input.value && api()) {
						e.preventDefault();
						e.stopPropagation();
						var submit = function() {
							form.submit();
						};
						fetchToken(input).then(submit, submit);
					}
				}, true);

				// Progressive enhancement: when jQuery is present, also hook
				// WooCommerce's jQuery-only checkout events for immediate
				// refreshes and a last-resort veto on the place-order event.
				if (window.jQuery) {
					var $ = window.jQuery;

					$(document.body).on('updated_checkout', queueRefresh);

					$(document.body).on('checkout_error', function() {
						clearCheckoutTokens();
						queueRefresh();
					});

					$(document.body).on('checkout_place_order', function() {
						var $form = $('form.woocommerce-checkout');
						var $input = $form.find('.g-recaptcha-response');

						if ($input.length && !$input.val() && api()) {
							var resubmit = function() {
								$form.trigger('submit');
							};
							fetchToken($input.get(0)).then(resubmit, resubmit);
							return false;
						}
						return true;
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
