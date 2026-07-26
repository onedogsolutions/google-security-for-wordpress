<?php
/**
 * reCAPTCHA Loader Conflict Notices
 *
 * Surfaces divergent-site-key conflicts detected on the front end by
 * GSWP_Recaptcha_Loader. Two severities, because the two states carry very
 * different risk:
 *
 *  - Warning  : another plugin loads reCAPTCHA with a different site key, and
 *               we are not suppressing it. Both loaders are on the page and one
 *               of them will fail to execute — only one key can be pre-rendered.
 *               Dismissible.
 *  - Critical : the same, except the Conflict Guard IS suppressing it. Another
 *               plugin's reCAPTCHA is being removed from pages, so its forms —
 *               including payment forms — may be failing right now. This is the
 *               state that broke Gravity Forms' Stripe checkout in 2.16.0, so
 *               it is not dismissible while it persists.
 *
 * Notices are shown site-wide on any screen the operator can act from, not just
 * this plugin's settings page: whoever never opens our settings is exactly who
 * needs to see this.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Loader_Notices {

	/**
	 * User meta storing the conflict hash a user has dismissed.
	 */
	const DISMISS_META = 'gswp_loader_conflict_dismissed';

	/**
	 * Query arg used to dismiss the warning-severity notice.
	 */
	const DISMISS_ARG = 'gswp_dismiss_loader_conflict';

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_init', array( $this, 'handle_dismiss' ) );
		add_action( 'after_plugin_row_' . plugin_basename( GSWP_FILE ), array( $this, 'render_plugin_row' ), 10, 2 );
	}

	/**
	 * Persist a dismissal, keyed to the conflict hash.
	 *
	 * Keying on the hash rather than a bare flag means a *changed* conflict —
	 * a different plugin, a different key, or suppression newly turning on —
	 * re-arms the notice instead of staying dismissed forever.
	 */
	public function handle_dismiss() {
		if ( ! isset( $_GET[ self::DISMISS_ARG ] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::DISMISS_ARG ) ) {
			return;
		}

		$conflict = GSWP_Recaptcha_Loader::stored_conflict();
		if ( null === $conflict || empty( $conflict['hash'] ) ) {
			return;
		}

		update_user_meta( get_current_user_id(), self::DISMISS_META, $conflict['hash'] );
	}

	/**
	 * The conflict to warn about on this screen, if any.
	 *
	 * @return array|null Conflict record, or null when there is nothing to show.
	 */
	private function active_conflict() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return null;
		}

		$conflict = GSWP_Recaptcha_Loader::stored_conflict();
		if ( null === $conflict || empty( $conflict['loaders'] ) ) {
			return null;
		}

		// The Critical state is never dismissible: another plugin's forms may
		// be failing while it persists.
		if ( ! empty( $conflict['suppressing'] ) ) {
			return $conflict;
		}

		$dismissed = get_user_meta( get_current_user_id(), self::DISMISS_META, true );
		if ( is_string( $dismissed ) && '' !== $dismissed && $dismissed === $conflict['hash'] ) {
			return null;
		}

		return $conflict;
	}

	/**
	 * Render the admin notice.
	 */
	public function render_notice() {
		$conflict = $this->active_conflict();
		if ( null === $conflict ) {
			return;
		}

		$critical = ! empty( $conflict['suppressing'] );
		$settings = admin_url( 'options-general.php?page=gswp-admin' );

		echo '<div class="notice ' . ( $critical ? 'notice-error' : 'notice-warning' ) . '">';

		echo '<p><strong>' . esc_html(
			$critical
				? __( 'Google Security: another plugin’s reCAPTCHA is being blocked', 'google-security-for-wordpress' )
				: __( 'Google Security: conflicting reCAPTCHA site key detected', 'google-security-for-wordpress' )
		) . '</strong></p>';

		echo '<p>' . esc_html(
			$critical
				? __( 'This plugin is removing another plugin’s reCAPTCHA script because it is configured with a different site key. That plugin’s forms — including payment forms such as Gravity Forms with Stripe — may be failing to submit.', 'google-security-for-wordpress' )
				: __( 'Another plugin is loading reCAPTCHA with a different site key than this plugin. Only one site key can be pre-rendered per page, so one of the two will fail to execute.', 'google-security-for-wordpress' )
		) . '</p>';

		echo '<ul style="list-style:disc;margin-left:20px;">';
		foreach ( $conflict['loaders'] as $loader ) {
			printf(
				'<li><code>%s</code> — %s <code>%s</code></li>',
				esc_html( $loader['handle'] ),
				esc_html__( 'site key', 'google-security-for-wordpress' ),
				esc_html( $loader['key'] )
			);
		}
		echo '</ul>';

		echo '<p>' . esc_html__( 'Fix this by setting both plugins to the same reCAPTCHA site key, or by setting reCAPTCHA Conflict Handling to “Disabled”.', 'google-security-for-wordpress' ) . '</p>';

		echo '<p><a class="button button-primary" href="' . esc_url( $settings ) . '">'
			. esc_html__( 'Open Google Security settings', 'google-security-for-wordpress' )
			. '</a>';

		if ( ! $critical ) {
			$dismiss = wp_nonce_url( add_query_arg( self::DISMISS_ARG, '1' ), self::DISMISS_ARG );
			echo ' <a class="button" href="' . esc_url( $dismiss ) . '">'
				. esc_html__( 'Dismiss', 'google-security-for-wordpress' )
				. '</a>';
		}

		echo '</p></div>';
	}

	/**
	 * Render a notice on this plugin's row on the Plugins screen.
	 *
	 * Only in the Critical state — this is the screen an operator reaches for
	 * during an incident when they are deciding what to deactivate, and it
	 * should tell them the cause before they guess.
	 *
	 * @param string $plugin_file Plugin file path (unused).
	 * @param array  $plugin_data Plugin data (unused).
	 */
	public function render_plugin_row( $plugin_file = '', $plugin_data = array() ) {
		$conflict = GSWP_Recaptcha_Loader::stored_conflict();
		if ( null === $conflict || empty( $conflict['suppressing'] ) || empty( $conflict['loaders'] ) ) {
			return;
		}

		$columns = function_exists( 'get_current_screen' ) && get_current_screen() && 'plugins-network' === get_current_screen()->id ? 5 : 4;

		echo '<tr class="plugin-update-tr active"><td colspan="' . (int) $columns . '" class="plugin-update colspanchange">';
		echo '<div class="update-message notice inline notice-error notice-alt"><p>';
		echo esc_html__( 'This plugin is currently blocking another plugin’s reCAPTCHA because their site keys differ. That plugin’s forms, including payment forms, may be failing.', 'google-security-for-wordpress' );
		echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=gswp-admin' ) ) . '">'
			. esc_html__( 'Review reCAPTCHA Conflict Handling', 'google-security-for-wordpress' )
			. '</a>';
		echo '</p></div></td></tr>';
	}
}
