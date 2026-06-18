<?php
/**
 * Admin Class
 *
 * Sets up the administrative submenu and enqueues scripts for the React application.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Admin {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_admin_page' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
	}

	/**
	 * Register the settings page under the core Settings menu.
	 */
	public function register_admin_page() {
		add_options_page(
			__( 'Google Security Settings', 'google-security-for-wordpress' ),
			__( 'Google Security', 'google-security-for-wordpress' ),
			'manage_options',
			'gswp-admin',
			array( $this, 'render_admin_page' )
		);
	}

	/**
	 * Render the administrative page mount container.
	 */
	public function render_admin_page() {
		?>
		<div class="wrap">
			<div id="gswp-admin-root" class="gswp-admin-isolated">
				<!-- The React application will mount here -->
				<p class="description"><?php esc_html_e( 'Loading reCAPTCHA settings...', 'google-security-for-wordpress' ); ?></p>
			</div>
		</div>
		<?php
	}

	/**
	 * Enqueue assets for our settings panel.
	 *
	 * @param string $hook The current admin page hook.
	 */
	public function enqueue_admin_assets( $hook ) {
		// Only load assets on our specific settings page.
		if ( 'settings_page_gswp-admin' !== $hook ) {
			return;
		}

		$asset_file_path = GSWP_PLUGIN_DIR . 'build/index.asset.php';
		$dependencies    = array( 'wp-element', 'wp-api-fetch', 'wp-i18n' );
		$version         = GSWP_VERSION;

		if ( file_exists( $asset_file_path ) ) {
			$asset_file   = include $asset_file_path;
			$dependencies = isset( $asset_file['dependencies'] ) ? $asset_file['dependencies'] : $dependencies;
			$version      = isset( $asset_file['version'] ) ? $asset_file['version'] : $version;
		}

		// Enqueue compiled script.
		wp_enqueue_script(
			'gswp-admin-js',
			GSWP_PLUGIN_URL . 'build/index.js',
			$dependencies,
			$version,
			true
		);

		// Enqueue compiled stylesheet.
		wp_enqueue_style(
			'gswp-admin-css',
			GSWP_PLUGIN_URL . 'build/index.css',
			array(),
			$version
		);

		// Fetch current settings to bootstrap the React app.
		$initial_settings = array(
			'site_key'               => get_option( 'gswp_site_key', '' ),
			'secret_key'             => get_option( 'gswp_secret_key', '' ),
			'key_type'               => get_option( 'gswp_key_type', 'classic' ),
			'gcp_project_id'         => get_option( 'gswp_gcp_project_id', '' ),
			'gcp_api_key'            => get_option( 'gswp_gcp_api_key', '' ),
			'enable_login'           => get_option( 'gswp_enable_login', '0' ),
			'enable_registration'    => get_option( 'gswp_enable_registration', '0' ),
			'enable_checkout'        => get_option( 'gswp_enable_checkout', '0' ),
			'threshold_login'        => get_option( 'gswp_threshold_login', '0.5' ),
			'threshold_registration' => get_option( 'gswp_threshold_registration', '0.5' ),
			'threshold_checkout'     => get_option( 'gswp_threshold_checkout', '0.5' ),
			'txn_defense'            => get_option( 'gswp_txn_defense', '0' ),
			'txn_block'              => get_option( 'gswp_txn_block', '0' ),
			'threshold_txn'          => get_option( 'gswp_threshold_txn', '0.8' ),
			'enable_wp_login'        => get_option( 'gswp_enable_wp_login', '0' ),
			'enable_wp_register'     => get_option( 'gswp_enable_wp_register', '0' ),
			'enable_wp_lostpassword' => get_option( 'gswp_enable_wp_lostpassword', '0' ),
			'threshold_wp_login'     => get_option( 'gswp_threshold_wp_login', '0.5' ),
			'threshold_wp_register'  => get_option( 'gswp_threshold_wp_register', '0.5' ),
			'threshold_wp_lostpassword' => get_option( 'gswp_threshold_wp_lostpassword', '0.5' ),
			'conflict_mode'          => get_option( 'gswp_conflict_mode', 'off' ),
			'tfa_enabled'            => get_option( 'gswp_2fa_enabled', '1' ),
			'tfa_enforced_roles'     => array_values( (array) get_option( 'gswp_2fa_enforced_roles', array() ) ),
		);

		// Localize script with REST endpoint variables and initial state.
		wp_localize_script(
			'gswp-admin-js',
			'gswpAdminData',
			array(
				'restUrl'            => esc_url_raw( rest_url( 'gswp/v1' ) ),
				'nonce'              => wp_create_nonce( 'wp_rest' ),
				'settings'           => $initial_settings,
				'woocommerceActive'  => class_exists( 'WooCommerce' ),
				'profileUrl'         => esc_url_raw( admin_url( 'profile.php' ) . '#gswp-2fa' ),
				'roles'              => wp_roles()->get_names(),
			)
		);
	}
}
