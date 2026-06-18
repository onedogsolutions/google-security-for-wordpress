<?php
/**
 * REST API Class
 *
 * Exposes REST API endpoints for settings management.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Rest_Api {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register REST API routes.
	 */
	public function register_routes() {
		register_rest_route(
			'gswp/v1',
			'/settings',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_settings' ),
					'permission_callback' => array( $this, 'check_permissions' ),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'update_settings' ),
					'permission_callback' => array( $this, 'check_permissions' ),
				),
			)
		);
	}

	/**
	 * Check capabilities for API access.
	 *
	 * @return bool True if authorized, false otherwise.
	 */
	public function check_permissions() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get settings callback.
	 *
	 * @return WP_REST_Response REST response containing settings.
	 */
	public function get_settings() {
		$settings = array(
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
			// Two-factor authentication.
			'tfa_enabled'            => get_option( 'gswp_2fa_enabled', '1' ),
			'tfa_enforced_roles'     => array_values( (array) get_option( 'gswp_2fa_enforced_roles', array() ) ),
		);

		return new WP_REST_Response( $settings, 200 );
	}

	/**
	 * Update settings callback.
	 *
	 * @param WP_REST_Request $request The REST request.
	 * @return WP_REST_Response REST response containing status or updated settings.
	 */
	public function update_settings( $request ) {
		$params = $request->get_params();

		// Sanitize and update Site Key.
		if ( isset( $params['site_key'] ) ) {
			update_option( 'gswp_site_key', sanitize_text_field( $params['site_key'] ) );
		}

		// Sanitize and update Secret Key.
		if ( isset( $params['secret_key'] ) ) {
			update_option( 'gswp_secret_key', sanitize_text_field( $params['secret_key'] ) );
		}

		// Key type. Only 'classic' or 'enterprise' are valid.
		if ( isset( $params['key_type'] ) ) {
			$key_type = 'enterprise' === $params['key_type'] ? 'enterprise' : 'classic';
			update_option( 'gswp_key_type', $key_type );
		}

		// Sanitize and update Enterprise credentials.
		if ( isset( $params['gcp_project_id'] ) ) {
			update_option( 'gswp_gcp_project_id', sanitize_text_field( $params['gcp_project_id'] ) );
		}
		if ( isset( $params['gcp_api_key'] ) ) {
			update_option( 'gswp_gcp_api_key', sanitize_text_field( $params['gcp_api_key'] ) );
		}

		// Toggles for WooCommerce (Login, Registration, Checkout) and the
		// WordPress core screens (Login, Registration, Lost Password).
		$toggles = array(
			'enable_login',
			'enable_registration',
			'enable_checkout',
			'txn_defense',
			'txn_block',
			'enable_wp_login',
			'enable_wp_register',
			'enable_wp_lostpassword',
		);
		foreach ( $toggles as $toggle ) {
			if ( isset( $params[ $toggle ] ) ) {
				update_option( 'gswp_' . $toggle, $params[ $toggle ] ? '1' : '0' );
			}
		}

		// Thresholds. Must validate they are floats between 0.0 and 1.0.
		$thresholds = array(
			'threshold_login',
			'threshold_registration',
			'threshold_checkout',
			'threshold_txn',
			'threshold_wp_login',
			'threshold_wp_register',
			'threshold_wp_lostpassword',
		);
		foreach ( $thresholds as $threshold ) {
			if ( isset( $params[ $threshold ] ) ) {
				$val = floatval( $params[ $threshold ] );
				$val = max( 0.0, min( 1.0, $val ) );
				update_option( 'gswp_' . $threshold, strval( $val ) );
			}
		}

		// Conflict handling mode. Only known modes are accepted.
		if ( isset( $params['conflict_mode'] ) ) {
			$mode = in_array( $params['conflict_mode'], array( 'off', 'active', 'site' ), true )
				? $params['conflict_mode']
				: 'off';
			update_option( 'gswp_conflict_mode', $mode );
		}

		// Two-factor: master switch.
		if ( isset( $params['tfa_enabled'] ) ) {
			update_option( 'gswp_2fa_enabled', $params['tfa_enabled'] ? '1' : '0' );
		}

		// Two-factor: roles required to enrol, validated against real roles.
		if ( isset( $params['tfa_enforced_roles'] ) ) {
			$submitted = is_array( $params['tfa_enforced_roles'] ) ? $params['tfa_enforced_roles'] : array();
			$valid     = array_keys( wp_roles()->get_names() );
			$roles     = array_values( array_intersect( array_map( 'sanitize_key', $submitted ), $valid ) );
			update_option( 'gswp_2fa_enforced_roles', $roles );
		}

		return $this->get_settings();
	}
}
