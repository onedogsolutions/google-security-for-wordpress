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
 * Since 2.18.0 this only ever applies to loaders configured with a site key
 * DIFFERENT from ours. A third-party loader carrying our own key is
 * deduplicated into a single shared tag by GSWP_Recaptcha_Loader and is never
 * suppressed — suppressing it is what broke Gravity Forms' Stripe payment
 * element in 2.16.0.
 *
 * Divergent keys cannot be resolved automatically: two Enterprise site keys
 * cannot both be pre-rendered via `?render=` on one page. Since 2.18.1 the
 * default response is to report that, not to resolve it — the operator is told
 * loudly through GSWP_Loader_Notices and decides. Only 'site' mode still
 * suppresses, and only because someone deliberately asked for it.
 *
 * Modes (gswp_conflict_mode):
 *  - 'off'    : non-destructive. Share matching-key loaders, report divergent
 *               ones, remove nothing.
 *  - 'active' : identical to 'off' since 2.18.1, and the recommended setting.
 *               Retained as a distinct stored value so no migration is needed.
 *  - 'site'   : the only mode that removes anything. Suppresses divergent-key
 *               loaders on every front-end page. Destructive by design and
 *               opt-in only: the other plugin's forms may stop working.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Conflict_Guard {

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
	 * Kept deliberately short. A handle with no src cannot be checked for which
	 * site key it carries, so suppressing on handle alone risks removing a
	 * loader that shares our key and would have been safely deduplicated. The
	 * Gravity Forms handles previously listed here were removed in 2.18.0 for
	 * exactly that reason.
	 *
	 * @var string[]
	 */
	private $handles = array(
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
		$mode = get_option( 'gswp_conflict_mode', 'off' );

		// Only 'site' suppresses. 'off' and 'active' are both non-destructive:
		// matching-key loaders are shared by GSWP_Recaptcha_Loader and divergent
		// ones are reported, never removed. Nothing to hook.
		if ( 'site' !== $mode ) {
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
		// Defensive: only 'site' mode reaches this filter at all.
		if ( 'site' !== $this->mode ) {
			return $tag;
		}

		// Never suppress a loader carrying OUR site key. Deduplication has
		// already collapsed it into a single tag (GSWP_Recaptcha_Loader), so
		// both plugins share one `grecaptcha` and nothing needs removing.
		// Suppressing a matching-key loader is what broke Gravity Forms'
		// Stripe payment element in 2.16.0; it is pure harm.
		$key = GSWP_Recaptcha_Loader::key_from_src( $src );
		if ( '' !== $key && $key === GSWP_Recaptcha_Loader::site_key() ) {
			return $tag;
		}

		if ( ! $this->should_suppress( $handle, $src ) ) {
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
		if ( GSWP_Assets::HANDLE === $handle ) {
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

}
