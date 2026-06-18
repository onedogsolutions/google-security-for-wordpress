<?php
/**
 * Shared Frontend Assets
 *
 * Centralizes loading of the Google reCAPTCHA API script and a generic token
 * refresh bootstrap so multiple integrations (WooCommerce, the Login/Signup
 * Popup plugin, Beaver Builder modules) can share one implementation.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Assets {

	/**
	 * Script handle for the Google reCAPTCHA API.
	 */
	const HANDLE = 'google-recaptcha-v3';

	/**
	 * Configured reCAPTCHA site key.
	 *
	 * @return string Site key, or empty string when unset.
	 */
	public static function site_key() {
		return get_option( 'gswp_site_key', '' );
	}

	/**
	 * Whether the Enterprise key type is configured.
	 *
	 * @return bool True for Enterprise, false for classic v3.
	 */
	public static function is_enterprise() {
		return 'enterprise' === get_option( 'gswp_key_type', 'classic' );
	}

	/**
	 * Register and enqueue the Google reCAPTCHA API script.
	 *
	 * Enterprise site keys load enterprise.js; classic v3 keys load api.js. No
	 * jQuery dependency: the bootstrap is vanilla JS so script optimizers that
	 * delay jQuery cannot delay token generation.
	 *
	 * @return bool True when enqueued, false when no site key is configured.
	 */
	public static function enqueue_api_script() {
		$site_key = self::site_key();
		if ( empty( $site_key ) ) {
			return false;
		}

		if ( ! wp_script_is( self::HANDLE, 'registered' ) ) {
			$script_base = self::is_enterprise()
				? 'https://www.google.com/recaptcha/enterprise.js'
				: 'https://www.google.com/recaptcha/api.js';

			wp_register_script(
				self::HANDLE,
				$script_base . '?render=' . rawurlencode( $site_key ),
				array(),
				GSWP_VERSION,
				true
			);
		}

		wp_enqueue_script( self::HANDLE );

		return true;
	}

	/**
	 * Attach the generic token refresh bootstrap to the API script once.
	 *
	 * Keeps every `.g-recaptcha-response` field on the page populated with a
	 * fresh token: fetched on load, refreshed before the two-minute expiry, on
	 * tab refocus, and whenever a matching field is added to the DOM. Suitable
	 * for AJAX login plugins that read the token value when serializing a form.
	 */
	public static function add_refresh_bootstrap() {
		static $added = false;
		if ( $added ) {
			return;
		}

		if ( ! wp_script_is( self::HANDLE, 'registered' ) ) {
			return;
		}

		wp_add_inline_script( self::HANDLE, self::get_refresh_js() );
		$added = true;
	}

	/**
	 * Build the generic token refresh bootstrap JavaScript.
	 *
	 * @return string Inline JavaScript.
	 */
	private static function get_refresh_js() {
		$site_key      = self::site_key();
		$is_enterprise = self::is_enterprise();

		ob_start();
		?>
		(function() {
			'use strict';

			if (window.gswpRefreshInit) {
				return;
			}
			window.gswpRefreshInit = true;

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

			function containsMatch(node) {
				if (node.nodeType !== 1) {
					return false;
				}
				return (node.matches && node.matches('.g-recaptcha-response')) ||
					!!node.querySelector('.g-recaptcha-response');
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

				// AJAX login plugins inject or reveal their forms dynamically;
				// refresh whenever a token field is added to the DOM.
				var observer = new MutationObserver(function(mutations) {
					for (var i = 0; i < mutations.length; i++) {
						var added = mutations[i].addedNodes;
						for (var j = 0; j < added.length; j++) {
							if (containsMatch(added[j])) {
								queueRefresh();
								return;
							}
						}
					}
				});
				observer.observe(document.body, { childList: true, subtree: true });
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
