<?php
/**
 * WooCommerce Blocks Integration Interface implementation.
 *
 * Registers the frontend script that runs inside the Checkout block, fetches a
 * fresh reCAPTCHA token just before submission, and attaches it to the Store
 * API request as `extensions.gswp.token`.
 *
 * This file is required lazily from GSWP_Blocks::register_integration(), i.e.
 * only once WooCommerce Blocks has loaded, so the IntegrationInterface it
 * implements is always defined at parse time here.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Blocks_Integration implements Automattic\WooCommerce\Blocks\Integrations\IntegrationInterface {

	/**
	 * Integration name. Also the key under which get_script_data() is exposed to
	 * the frontend (as `gswp-recaptcha_data`).
	 *
	 * @return string
	 */
	public function get_name() {
		return 'gswp-recaptcha';
	}

	/**
	 * Register the frontend script and the Google reCAPTCHA API loader.
	 *
	 * The block script is a hand-written asset (like assets/js/gswp-2fa-modal.js)
	 * that reads runtime globals, so it needs no build step. Its dependency
	 * handles make WordPress load the block runtime (wp-element, wp-plugins,
	 * wp-data, wp-i18n), the WooCommerce checkout package (wc-blocks-checkout,
	 * exposing window.wc.blocksCheckout), and the Google reCAPTCHA loader.
	 */
	public function initialize() {
		// Registration is owned by GSWP_Recaptcha_Loader so the Store API path
		// shares one loader with the rest of the plugin — and so the handle is
		// always registered, which matters because the block script below lists
		// it as a dependency and WordPress silently refuses to enqueue a script
		// whose dependency is unregistered.
		GSWP_Recaptcha_Loader::ensure_registered();

		$dependencies = array(
			'wp-element',
			'wp-plugins',
			'wp-data',
			'wp-i18n',
			'wc-blocks-checkout',
			'google-recaptcha-v3',
		);

		wp_register_script(
			'gswp-blocks-checkout',
			GSWP_PLUGIN_URL . 'assets/js/gswp-blocks-checkout.js',
			$dependencies,
			GSWP_VERSION,
			true
		);

		wp_localize_script(
			'gswp-blocks-checkout',
			'gswpBlocksData',
			$this->get_script_data()
		);
	}

	/**
	 * Frontend script handles enqueued in the checkout block context.
	 *
	 * @return string[]
	 */
	public function get_script_handles() {
		return array( 'gswp-blocks-checkout', 'google-recaptcha-v3' );
	}

	/**
	 * Editor script handles. None: the block needs no editor-side behaviour.
	 *
	 * @return string[]
	 */
	public function get_editor_script_handles() {
		return array();
	}

	/**
	 * Data exposed to the frontend script.
	 *
	 * @return array
	 */
	public function get_script_data() {
		return array(
			'siteKey'      => get_option( 'gswp_site_key', '' ),
			'isEnterprise' => 'enterprise' === get_option( 'gswp_key_type', 'classic' ),
			'enabled'      => '1' === get_option( 'gswp_enable_checkout', '0' ),
		);
	}
}
