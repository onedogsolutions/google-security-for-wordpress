<?php
/**
 * Key Scavenger Class
 *
 * Scavenges existing reCAPTCHA keys from other popular plugins.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Key_Scavenger {

	/**
	 * Scavenges keys from various plugin settings in the database.
	 *
	 * Each result carries a 'version' ('v2', 'v3', or 'unknown') and an
	 * 'importable' flag: v2 checkbox keys are rejected because this plugin
	 * executes reCAPTCHA v3, which cannot use v2 site keys.
	 *
	 * @return array Discovered credentials.
	 */
	public static function scan() {
		$results = array();

		// 1. Fluent Forms.
		// Credentials live in the dedicated _fluentform_reCaptcha_details
		// option (keys: siteKey, secretKey, api_version).
		$fluent_recaptcha = get_option( '_fluentform_reCaptcha_details' );
		if ( ! is_array( $fluent_recaptcha ) ) {
			// Fall back to legacy global settings shapes.
			$fluent_settings = get_option( 'fluentform_global_settings' );
			if ( ! is_array( $fluent_settings ) ) {
				$fluent_settings = get_option( 'fluentform_settings' );
			}
			if ( is_array( $fluent_settings ) && isset( $fluent_settings['reCaptcha'] ) && is_array( $fluent_settings['reCaptcha'] ) ) {
				$fluent_recaptcha = $fluent_settings['reCaptcha'];
			}
		}

		if ( is_array( $fluent_recaptcha ) ) {
			$site_key   = isset( $fluent_recaptcha['siteKey'] ) ? sanitize_text_field( $fluent_recaptcha['siteKey'] ) : '';
			$secret_key = isset( $fluent_recaptcha['secretKey'] ) ? sanitize_text_field( $fluent_recaptcha['secretKey'] ) : '';
			$version    = self::normalize_version( isset( $fluent_recaptcha['api_version'] ) ? $fluent_recaptcha['api_version'] : '' );

			if ( ! empty( $site_key ) ) {
				$results[] = array(
					'source'     => 'Fluent Forms',
					'site_key'   => $site_key,
					'secret_key' => $secret_key,
					'version'    => $version,
					'importable' => 'v2' !== $version,
				);
			}
		}

		// 2. Gravity Forms.
		// 2a. reCAPTCHA Add-On settings (stores v3 keys under
		// version-suffixed field names).
		$gf_settings = get_option( 'gravityformsaddon_gravityformsrecaptcha_settings' );
		if ( ! is_array( $gf_settings ) ) {
			$gf_settings = get_option( 'rg_gforms_setting' );
		}
		if ( ! is_array( $gf_settings ) ) {
			$gf_settings = get_option( 'gform_setting' );
		}

		if ( is_array( $gf_settings ) ) {
			$version    = 'unknown';
			$site_key   = '';
			$secret_key = '';

			if ( ! empty( $gf_settings['site_key_v3'] ) ) {
				$site_key   = sanitize_text_field( $gf_settings['site_key_v3'] );
				$secret_key = isset( $gf_settings['secret_key_v3'] ) ? sanitize_text_field( $gf_settings['secret_key_v3'] ) : '';
				$version    = 'v3';
			} elseif ( ! empty( $gf_settings['site_key'] ) ) {
				$site_key   = sanitize_text_field( $gf_settings['site_key'] );
				$secret_key = isset( $gf_settings['secret_key'] ) ? sanitize_text_field( $gf_settings['secret_key'] ) : '';
			} elseif ( ! empty( $gf_settings['publickey'] ) ) {
				$site_key   = sanitize_text_field( $gf_settings['publickey'] );
				$secret_key = isset( $gf_settings['privatekey'] ) ? sanitize_text_field( $gf_settings['privatekey'] ) : '';
			}

			if ( ! empty( $site_key ) ) {
				$results[] = array(
					'source'     => 'Gravity Forms',
					'site_key'   => $site_key,
					'secret_key' => $secret_key,
					'version'    => $version,
					'importable' => true,
				);
			}
		}

		// 2b. Gravity Forms classic core settings: the built-in CAPTCHA
		// field stores its v2 keys as standalone string options.
		$gf_public = get_option( 'rg_gforms_captcha_public_key' );
		if ( is_string( $gf_public ) && '' !== trim( $gf_public ) ) {
			$gf_private = get_option( 'rg_gforms_captcha_private_key' );

			$results[] = array(
				'source'     => 'Gravity Forms (Classic)',
				'site_key'   => sanitize_text_field( $gf_public ),
				'secret_key' => is_string( $gf_private ) ? sanitize_text_field( $gf_private ) : '',
				'version'    => 'v2',
				'importable' => false,
			);
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
					'version'    => 'unknown',
					'importable' => true,
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
										'version'    => 'unknown',
										'importable' => true,
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
					'version'    => 'unknown',
					'importable' => true,
				);
			}
		}

		return $results;
	}

	/**
	 * Normalize a plugin-specific reCAPTCHA version value to 'v2'/'v3'/'unknown'.
	 *
	 * Fluent Forms stores api_version as 2/3 (older releases used string
	 * labels), so match defensively.
	 *
	 * @param mixed $raw Raw version value from another plugin's settings.
	 * @return string Normalized version identifier.
	 */
	private static function normalize_version( $raw ) {
		$value = strtolower( trim( (string) $raw ) );

		if ( in_array( $value, array( '3', 'v3', 'v3_invisible' ), true ) ) {
			return 'v3';
		}

		if ( in_array( $value, array( '2', 'v2', 'v2_visible', 'v2_invisible', 'v2_checkbox' ), true ) ) {
			return 'v2';
		}

		return 'unknown';
	}
}
