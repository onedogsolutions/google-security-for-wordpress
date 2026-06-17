<?php
/**
 * reCAPTCHA Conflict Guard
 *
 * Suppresses reCAPTCHA scripts loaded by other plugins so this plugin's single
 * implementation is the only one on the page. Google recommends loading
 * reCAPTCHA only once per page; multiple loaders (e.g. Gravity Forms' own
 * reCAPTCHA alongside this plugin) conflict and break token generation.
 *
 * Replaces hand-rolled wp_dequeue_script() snippets: rather than matching a
 * fixed list of handles on a specific page, it suppresses any script whose
 * source loads Google reCAPTCHA at render time, which is robust across plugins
 * and versions.
 *
 * Modes (recaptcha_woo_conflict_mode):
 *  - 'off'    : do nothing (default).
 *  - 'active' : suppress others only on pages where this plugin loads its own
 *               reCAPTCHA. Standalone reCAPTCHA on other pages keeps working.
 *  - 'site'   : suppress others on every front-end page.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Conflict_Guard {

	/**
	 * Active suppression mode ('active' or 'site').
	 *
	 * @var string
	 */
	private $mode;

	/**
	 * Known third-party reCAPTCHA script handles that do not always carry a
	 * matchable src (registered as dependencies, inline config, etc.).
	 *
	 * @var string[]
	 */
	private $handles = array(
		// Gravity Forms core and reCAPTCHA Add-On.
		'gform_recaptcha',
		'gform_recaptcha_v3',
		'gforms_recaptcha_frontend',
		'gforms_recaptcha_recaptcha',
		// PowerPack (Beaver Builder) reCAPTCHA loader.
		'g-recaptcha',
	);

	/**
	 * Source fragments that identify a Google reCAPTCHA loader.
	 *
	 * @var string[]
	 */
	private $src_needles = array(
		'google.com/recaptcha',
		'recaptcha.net/recaptcha',
		'gstatic.com/recaptcha',
	);

	/**
	 * Constructor.
	 */
	public function __construct() {
		$mode = get_option( 'recaptcha_woo_conflict_mode', 'off' );

		if ( 'active' !== $mode && 'site' !== $mode ) {
			return;
		}

		// Only touch front-end (and wp-login.php) output, never wp-admin.
		if ( is_admin() ) {
			return;
		}

		$this->mode = $mode;
		add_filter( 'script_loader_tag', array( $this, 'filter_tag' ), 10, 3 );
	}

	/**
	 * Suppress the script tag for conflicting reCAPTCHA loaders.
	 *
	 * @param string $tag    The full script tag.
	 * @param string $handle The script handle.
	 * @param string $src    The script source URL.
	 * @return string The original tag, or an empty string to suppress it.
	 */
	public function filter_tag( $tag, $handle, $src ) {
		if ( ! $this->should_suppress( $handle, $src ) ) {
			return $tag;
		}

		// In 'active' mode only strip others where our own reCAPTCHA runs.
		if ( 'active' === $this->mode && ! $this->our_recaptcha_active() ) {
			return $tag;
		}

		return '';
	}

	/**
	 * Whether a handle/src belongs to a third-party reCAPTCHA loader.
	 *
	 * @param string $handle The script handle.
	 * @param string $src    The script source URL.
	 * @return bool True when it should be suppressed.
	 */
	private function should_suppress( $handle, $src ) {
		// Never suppress this plugin's own script.
		if ( Recaptcha_Woo_Assets::HANDLE === $handle ) {
			return false;
		}

		if ( in_array( $handle, $this->handles, true ) ) {
			return true;
		}

		if ( empty( $src ) ) {
			return false;
		}

		foreach ( $this->src_needles as $needle ) {
			if ( false !== strpos( $src, $needle ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether this plugin enqueued its own reCAPTCHA script on this request.
	 *
	 * @return bool True when this plugin's script is in the queue.
	 */
	private function our_recaptcha_active() {
		return wp_script_is( Recaptcha_Woo_Assets::HANDLE, 'enqueued' )
			|| wp_script_is( Recaptcha_Woo_Assets::HANDLE, 'done' );
	}
}
