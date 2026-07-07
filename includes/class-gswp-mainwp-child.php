<?php
/**
 * MainWP child-side bridge.
 *
 * Lets the "MainWP for Google Security for WordPress" dashboard extension read
 * and update this plugin's settings over MainWP's signed dashboard-to-child
 * channel. Requests arrive only through MainWP Child's 'extra_execution'
 * callable, strictly after its RSA-signature authentication, running as the
 * connected admin user - so the REST callbacks are invoked directly and no
 * capability re-check happens here. Inert unless MainWP Child dispatches the
 * filter with our action key.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_MainWP_Child {

	/**
	 * Constructor.
	 *
	 * Subscribes to MainWP Child's extra_execution filter (MainWP Child 4.0+).
	 * When MainWP Child is absent the filter is never fired, so registering it
	 * has no effect.
	 */
	public function __construct() {
		add_filter( 'mainwp_child_extra_execution', array( $this, 'handle' ), 10, 2 );
	}

	/**
	 * Answer the dashboard extension's get_settings / update_settings actions.
	 *
	 * Only the 'mwpgswp' key is ever added to $information; requests that do
	 * not carry our action key pass through untouched so other MainWP
	 * extensions sharing this filter are never disturbed.
	 *
	 * @param array $information Response accumulator shared by all subscribers.
	 * @param array $post        The raw (slashed) POST of the child request.
	 * @return array $information, with 'mwpgswp' added when the request is ours.
	 */
	public function handle( $information, $post ) {
		if ( ! is_array( $post ) || empty( $post['mwpgswp_action'] ) ) {
			return $information;
		}

		$rest   = new GSWP_Rest_Api();
		$action = wp_unslash( $post['mwpgswp_action'] );

		if ( 'get_settings' === $action ) {
			$settings = $rest->get_settings()->get_data();
		} elseif ( 'update_settings' === $action ) {
			$incoming = json_decode( isset( $post['settings'] ) ? wp_unslash( $post['settings'] ) : '', true );
			if ( ! is_array( $incoming ) ) {
				$information['mwpgswp'] = array(
					'success' => false,
					'error'   => 'invalid settings payload',
				);
				return $information;
			}
			// Route through the REST callback so every validation rule
			// (threshold clamping, enum whitelists, email/login/role
			// validation, the alert-mode cron reschedule) applies unchanged.
			$request = new WP_REST_Request( 'POST', '/gswp/v1/settings' );
			foreach ( $incoming as $key => $value ) {
				$request->set_param( $key, $value );
			}
			$settings = $rest->update_settings( $request )->get_data();
		} else {
			$information['mwpgswp'] = array(
				'success' => false,
				'error'   => 'unknown action',
			);
			return $information;
		}

		$information['mwpgswp'] = array(
			'success'            => true,
			'version'            => GSWP_VERSION,
			'woocommerce_active' => class_exists( 'WooCommerce' ),
			'roles'              => wp_roles()->get_names(),
			'settings'           => $settings,
		);

		return $information;
	}
}
