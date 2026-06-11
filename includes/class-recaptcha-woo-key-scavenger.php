<?php
/**
 * Key Scavenger Class
 *
 * Scavenges existing reCAPTCHA keys from other popular plugins.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Key_Scavenger {

	/**
	 * Scavenges keys from various plugin settings in the database.
	 *
	 * @return array Discovered credentials.
	 */
	public static function scan() {
		$results = array();

		// 1. Fluent Forms.
		$fluent_settings = get_option( 'fluentform_global_settings' );
		if ( ! is_array( $fluent_settings ) ) {
			$fluent_settings = get_option( 'fluentform_settings' );
		}
		if ( is_array( $fluent_settings ) && isset( $fluent_settings['reCaptcha'] ) ) {
			$re_captcha = $fluent_settings['reCaptcha'];
			$site_key   = isset( $re_captcha['siteKey'] ) ? sanitize_text_field( $re_captcha['siteKey'] ) : '';
			$secret_key = isset( $re_captcha['secretKey'] ) ? sanitize_text_field( $re_captcha['secretKey'] ) : '';

			if ( ! empty( $site_key ) ) {
				$results[] = array(
					'source'     => 'Fluent Forms',
					'site_key'   => $site_key,
					'secret_key' => $secret_key,
				);
			}
		}

		// 2. Gravity Forms.
		// Check both common Gravity Forms settings options.
		$gf_settings = get_option( 'gravityformsaddon_gravityformsrecaptcha_settings' );
		if ( ! is_array( $gf_settings ) ) {
			$gf_settings = get_option( 'rg_gforms_setting' );
		}
		if ( ! is_array( $gf_settings ) ) {
			$gf_settings = get_option( 'gform_setting' );
		}

		if ( is_array( $gf_settings ) ) {
			$site_key   = isset( $gf_settings['site_key'] ) ? sanitize_text_field( $gf_settings['site_key'] ) : ( isset( $gf_settings['publickey'] ) ? sanitize_text_field( $gf_settings['publickey'] ) : '' );
			$secret_key = isset( $gf_settings['secret_key'] ) ? sanitize_text_field( $gf_settings['secret_key'] ) : ( isset( $gf_settings['privatekey'] ) ? sanitize_text_field( $gf_settings['privatekey'] ) : '' );

			if ( ! empty( $site_key ) ) {
				$results[] = array(
					'source'     => 'Gravity Forms',
					'site_key'   => $site_key,
					'secret_key' => $secret_key,
				);
			}
		}

		// 3. Beaver Builder.
		// Check fl_builder_settings option first.
		$bb_settings = get_option( 'fl_builder_settings' );
		if ( is_array( $bb_settings ) ) {
			$site_key   = isset( $bb_settings['recaptcha_site_key'] ) ? sanitize_text_field( $bb_settings['recaptcha_site_key'] ) : '';
			$secret_key = isset( $bb_settings['recaptcha_secret_key'] ) ? sanitize_text_field( $bb_settings['recaptcha_secret_key'] ) : '';

			if ( ! empty( $site_key ) ) {
				$results[] = array(
					'source'     => 'Beaver Builder Settings',
					'site_key'   => $site_key,
					'secret_key' => $secret_key,
				);
			}
		}

		// Query wp_postmeta to find any embedded BB modules with keys.
		// Limit to 50 results to prevent performance hogging.
		global $wpdb;
		$bb_meta = $wpdb->get_results(
			"SELECT meta_value FROM {$wpdb->postmeta} WHERE meta_key = '_fl_builder_data' AND meta_value LIKE '%recaptcha_site_key%' LIMIT 50",
			ARRAY_A
		);

		if ( is_array( $bb_meta ) ) {
			foreach ( $bb_meta as $row ) {
				$layout_data = maybe_unserialize( $row['meta_value'] );
				if ( is_array( $layout_data ) || is_object( $layout_data ) ) {
					foreach ( (array) $layout_data as $node ) {
						if ( is_object( $node ) && isset( $node->settings ) ) {
							$settings = $node->settings;
							if ( isset( $settings->recaptcha_site_key ) && ! empty( $settings->recaptcha_site_key ) ) {
								$site_key   = sanitize_text_field( $settings->recaptcha_site_key );
								$secret_key = isset( $settings->recaptcha_secret_key ) ? sanitize_text_field( $settings->recaptcha_secret_key ) : '';

								// Check if already found.
								$duplicate = false;
								foreach ( $results as $res ) {
									if ( $res['site_key'] === $site_key ) {
										$duplicate = true;
										break;
									}
								}
								if ( ! $duplicate ) {
									$results[] = array(
										'source'     => 'Beaver Builder Postmeta',
										'site_key'   => $site_key,
										'secret_key' => $secret_key,
									);
								}
							}
						}
					}
				}
			}
		}

		// 4. PowerPack for Beaver Builder.
		$pp_settings = get_option( 'bb_powerpack_settings' );
		if ( ! is_array( $pp_settings ) ) {
			$pp_settings = get_option( 'powerpack_settings' );
		}

		if ( is_array( $pp_settings ) ) {
			$site_key   = isset( $pp_settings['recaptcha_site_key'] ) ? sanitize_text_field( $pp_settings['recaptcha_site_key'] ) : '';
			$secret_key = isset( $pp_settings['recaptcha_secret_key'] ) ? sanitize_text_field( $pp_settings['recaptcha_secret_key'] ) : '';

			if ( ! empty( $site_key ) ) {
				$results[] = array(
					'source'     => 'PowerPack Addons',
					'site_key'   => $site_key,
					'secret_key' => $secret_key,
				);
			}
		}

		return $results;
	}
}
