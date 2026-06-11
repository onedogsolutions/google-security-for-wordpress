<?php
/**
 * Frontend Class
 *
 * Handles public enqueuing of the Google reCAPTCHA scripts and form hidden inputs.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Frontend {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'wp_enqueue_scripts', array( $this, 'register_scripts' ) );

		// Check if forms are enabled and hook accordingly.
		if ( '1' === get_option( 'recaptcha_woo_enable_login', '0' ) ) {
			add_action( 'woocommerce_login_form_end', array( $this, 'inject_recaptcha_field' ) );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_registration', '0' ) ) {
			add_action( 'woocommerce_register_form_end', array( $this, 'inject_recaptcha_field' ) );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_checkout', '0' ) ) {
			add_action( 'woocommerce_review_order_before_submit', array( $this, 'inject_recaptcha_field' ) );
		}
	}

	/**
	 * Register the Google reCAPTCHA v3 script.
	 */
	public function register_scripts() {
		$site_key = get_option( 'recaptcha_woo_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		// Register Google API script.
		wp_register_script(
			'google-recaptcha-v3',
			'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ),
			array(),
			RECAPTCHA_WOO_VERSION,
			true
		);
	}

	/**
	 * Inject hidden reCAPTCHA response fields into the form.
	 */
	public function inject_recaptcha_field() {
		$site_key = get_option( 'recaptcha_woo_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		// Ensure the API script is enqueued.
		wp_enqueue_script( 'google-recaptcha-v3' );

		// Print the hidden input field.
		echo '<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" value="" />';

		// Render the JS once.
		static $js_printed = false;
		if ( ! $js_printed ) {
			$this->print_inline_js( $site_key );
			$js_printed = true;
		}
	}

	/**
	 * Print inline JavaScript to trigger reCAPTCHA execution before submission.
	 *
	 * @param string $site_key The reCAPTCHA site key.
	 */
	private function print_inline_js( $site_key ) {
		?>
		<script type="text/javascript">
			(function($) {
				$(document).ready(function() {
					var siteKey = <?php echo wp_json_encode( $site_key ); ?>;

					// 1. Intercept standard forms (Login, Register).
					$(document).on('submit', 'form.login, form.register', function(e) {
						var $form = $(this);
						var $input = $form.find('.g-recaptcha-response');

						if ($input.length && !$input.val()) {
							e.preventDefault();
							if (typeof grecaptcha !== 'undefined') {
								grecaptcha.ready(function() {
									var action = $form.hasClass('register') ? 'register' : 'login';
									grecaptcha.execute(siteKey, { action: action }).then(function(token) {
										$input.val(token);
										$form.submit();
									});
								});
							} else {
								// Fallback if reCAPTCHA script didn't load properly.
								$form.submit();
							}
						}
					});

					// 2. Intercept WooCommerce Checkout AJAX submission.
					$(document.body).on('checkout_place_order', function() {
						var $form = $('form.woocommerce-checkout');
						var $input = $form.find('.g-recaptcha-response');

						if ($input.length && !$input.val()) {
							if (typeof grecaptcha !== 'undefined') {
								grecaptcha.ready(function() {
									grecaptcha.execute(siteKey, { action: 'checkout' }).then(function(token) {
										$input.val(token);
										$form.submit();
									});
								});
								return false;
							}
						}
						return true;
					});

					// Clear the checkout token on error so a fresh one is fetched.
					$(document.body).on('checkout_error', function() {
						$('form.woocommerce-checkout').find('.g-recaptcha-response').val('');
					});
				});
			})(jQuery);
		</script>
		<?php
	}
}
