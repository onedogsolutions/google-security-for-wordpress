<?php
/**
 * GF replacement verification — chunk 1: preflight (v2.20.0)
 *
 * Read-only. Confirms the site is in a state where the remaining chunks mean
 * anything. Run this first; if it fails, stop and report — the later chunks
 * will produce misleading passes on a misconfigured site.
 *
 * Run via an MCP PHP-execution tool or `wp eval-file`.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Run context. Printed by every chunk so a result can always be tied to the
// plugin version and site that produced it — two earlier rounds were read
// against the wrong version because the output carried no provenance.
$gswp_ctx = array(
	'=== RUN CONTEXT ===',
	'  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ),
	'  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ),
	'  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ),
	'  php            : ' . PHP_VERSION,
	'',
);
echo implode( "\n", $gswp_ctx ) . "\n";

$out = array();
$ok  = true;

$line = function ( $label, $value, $good = null ) use ( &$out, &$ok ) {
	$mark = '';
	if ( true === $good ) {
		$mark = 'OK   ';
	} elseif ( false === $good ) {
		$mark = 'FAIL ';
		$ok   = false;
	} else {
		$mark = '     ';
	}
	$out[] = $mark . str_pad( $label, 38 ) . $value;
};

$out[] = '=== GF replacement preflight ===';

// Plugin.
$version = defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'not active';
$line( 'Plugin version', $version, defined( 'GSWP_VERSION' ) && version_compare( GSWP_VERSION, '2.20.0', '>=' ) );

$line( 'Provider registry loaded', class_exists( 'GSWP_Form_Provider_Registry' ) ? 'yes' : 'no', class_exists( 'GSWP_Form_Provider_Registry' ) );
$line( 'GF provider loaded', class_exists( 'GSWP_Provider_Gravity_Forms' ) ? 'yes' : 'no', class_exists( 'GSWP_Provider_Gravity_Forms' ) );

if ( ! class_exists( 'GSWP_Form_Provider_Registry' ) ) {
	$out[] = '';
	$out[] = 'STOP: plugin not active or older than 2.20.0.';
	echo implode( "\n", $out ) . "\n";
	return;
}

// Gravity Forms.
$gf = class_exists( 'GFAPI' );
$line( 'Gravity Forms active', $gf ? ( defined( 'GF_VERSION' ) ? GF_VERSION : 'yes' ) : 'no', $gf );

// Credentials.
$site_key = GSWP_Recaptcha_Loader::site_key();
$line( 'reCAPTCHA site key configured', '' !== $site_key ? 'yes' : 'NO', '' !== $site_key );
$line( 'Key type', get_option( 'gswp_key_type', 'classic' ), null );

$enterprise = 'enterprise' === get_option( 'gswp_key_type', 'classic' );
if ( $enterprise ) {
	$line( 'GCP project id set', '' !== get_option( 'gswp_gcp_project_id', '' ) ? 'yes' : 'NO', '' !== get_option( 'gswp_gcp_project_id', '' ) );
	$line( 'GCP API key set', '' !== get_option( 'gswp_gcp_api_key', '' ) ? 'yes' : 'NO', '' !== get_option( 'gswp_gcp_api_key', '' ) );
	$line( 'Transaction Defense enabled', '1' === get_option( 'gswp_txn_defense', '0' ) ? 'yes' : 'no', null );
	$line( 'High-risk blocking enabled', '1' === get_option( 'gswp_txn_block', '0' ) ? 'yes' : 'no', null );
}

// Replacement state.
$line( 'Form protection master switch', GSWP_Form_Provider_Registry::enabled() ? 'enabled' : 'DISABLED', null );
$line( 'GF replacement', GSWP_Form_Provider_Registry::is_on( 'gravity-forms' ) ? 'ON' : 'off', null );
$line( 'Kill-switch constant defined', defined( 'GSWP_DISABLE_FORM_PROVIDERS' ) ? 'yes' : 'no', null );

// Forms.
if ( $gf ) {
	$provider = GSWP_Form_Provider_Registry::get( 'gravity-forms' );
	$forms    = $provider ? $provider->forms() : array();
	$line( 'Gravity Forms found', (string) count( $forms ), count( $forms ) > 0 );

	$payment = 0;
	$inel    = 0;
	foreach ( array_keys( $forms ) as $form_id ) {
		if ( $provider->form_has_payment( $form_id ) ) {
			++$payment;
		}
		if ( ! $provider->form_is_eligible( $form_id ) ) {
			++$inel;
		}
	}
	$line( '  of which take payment', (string) $payment, null );
	$line( '  of which are ineligible (v2)', (string) $inel, null );
}

$out[] = '';
$out[] = $ok ? 'PREFLIGHT PASSED — continue to chunk 12.' : 'PREFLIGHT FAILED — fix the FAIL lines before continuing.';
$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
