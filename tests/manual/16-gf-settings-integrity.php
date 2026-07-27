<?php
/**
 * GF replacement verification — chunk 6: Gravity Forms settings integrity
 *
 * Read-only, and deliberately reads the database directly.
 *
 * Versions 2.20.4 and earlier applied the "stand down GF's reCAPTCHA" filter on
 * admin screens as well as the front end. Gravity Forms' own reCAPTCHA settings
 * page reads that option to populate its fields and writes back what it read, so
 * on those versions the page showed empty keys, refused to save correctly, and
 * could have persisted the blanks over the real values.
 *
 * That would break the guarantee the whole mechanism rests on — that nothing is
 * ever written to the host plugin's configuration. This checks whether it
 * happened, by reading the raw option rows with $wpdb rather than get_option(),
 * which would come back through the very filter in question.
 *
 * Run this BEFORE touching the Gravity Forms settings page again.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

$gswp_ctx = array(
	'=== RUN CONTEXT ===',
	'  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ),
	'  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ),
	'  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ),
	'  php            : ' . PHP_VERSION,
	'',
);
echo implode( "\n", $gswp_ctx ) . "\n";

$mask = function ( $value ) {
	$value = (string) $value;
	if ( '' === $value ) {
		return '(EMPTY)';
	}
	if ( strlen( $value ) <= 10 ) {
		return $value;
	}
	return substr( $value, 0, 6 ) . '…' . substr( $value, -4 );
};

$out   = array();
$out[] = '=== Gravity Forms reCAPTCHA settings integrity ===';
$out[] = '';

$options = array(
	'gravityformsaddon_gravityformsrecaptcha_settings',
	'gravityformsaddon_recaptcha_settings',
	'gravityformsaddon_gravityformsrecaptcha_v2_settings',
);

$found_any = false;
$intact    = false;

foreach ( $options as $option ) {
	// Raw read: get_option() would pass through this plugin's blanking filter
	// and could not tell an emptied option from a filtered one.
	$raw = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

	if ( null === $raw ) {
		continue;
	}

	$found_any = true;
	$settings  = maybe_unserialize( $raw );

	$out[] = $option;

	if ( ! is_array( $settings ) ) {
		$out[] = '  (not an array — value: ' . $mask( (string) $raw ) . ')';
		$out[] = '';
		continue;
	}

	foreach ( array( 'site_key_v3', 'secret_key_v3', 'site_key_v2', 'secret_key_v2', 'connection_type', 'recaptcha_keys_status_v3' ) as $k ) {
		if ( array_key_exists( $k, $settings ) ) {
			$v = $settings[ $k ];
			$out[] = '  ' . str_pad( $k, 26 ) . ( is_scalar( $v ) ? $mask( (string) $v ) : '(' . gettype( $v ) . ')' );
		}
	}

	if ( ! empty( $settings['site_key_v3'] ) || ! empty( $settings['site_key_v2'] ) ) {
		$intact = true;
	}

	// Compare against what get_option() returns, so the effect of the filter is
	// visible rather than inferred.
	$filtered = get_option( $option );
	if ( is_array( $filtered ) ) {
		$fk = isset( $filtered['site_key_v3'] ) ? (string) $filtered['site_key_v3'] : '';
		$rk = isset( $settings['site_key_v3'] ) ? (string) $settings['site_key_v3'] : '';
		$out[] = '  --';
		$out[] = '  raw site_key_v3           ' . $mask( $rk );
		$out[] = '  as this plugin sees it    ' . $mask( $fk )
			. ( $rk !== $fk ? '   <- blanking filter is active in this context' : '   <- filter not active here' );
	}

	$out[] = '';
}

if ( ! $found_any ) {
	$out[] = 'No Gravity Forms reCAPTCHA settings option exists in the database at all.';
	$out[] = 'Either the add-on has never been configured, or the option was deleted.';
} elseif ( $intact ) {
	$out[] = 'RESULT: the stored keys are INTACT. Nothing was overwritten.';
	$out[] = '';
	$out[] = 'The Gravity Forms settings page appeared empty because this plugin was';
	$out[] = 'filtering the option on admin screens too. Fixed in 2.20.5 — the filter';
	$out[] = 'now applies only on the front end and to AJAX form submissions, never';
	$out[] = 'to an admin page. The settings page should behave normally again.';
} else {
	$out[] = '*** RESULT: the stored site keys are EMPTY. ***';
	$out[] = '';
	$out[] = 'Gravity Forms has most likely saved this plugin\'s blanked values over';
	$out[] = 'the real ones while the settings page was being filtered. The keys';
	$out[] = 'themselves are not lost — they are in the Google reCAPTCHA console,';
	$out[] = 'and the same site key is still configured in this plugin.';
	$out[] = '';
	$out[] = 'To recover, on 2.20.5 or later:';
	$out[] = '  1. Confirm this plugin reports the filter as NOT active above.';
	$out[] = '  2. Re-enter the key and secret on the Gravity Forms reCAPTCHA';
	$out[] = '     settings page and save.';
	$out[] = '  3. Re-run this chunk to confirm the values persisted.';
}

$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
