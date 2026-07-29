<?php
/**
 * Fluent Forms replacement verification — chunk 20: preflight (v2.23.0)
 *
 * Read-only. Confirms the site is in a state where the remaining chunks mean
 * anything, and settles the `is_active()` binding by printing what actually
 * exists rather than what we guessed.
 *
 * Run this first; if it fails, stop and report — the later chunks will produce
 * misleading passes on a misconfigured site.
 *
 * Run via an MCP PHP-execution tool or `wp eval-file`.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

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
	$mark = '     ';
	if ( true === $good ) {
		$mark = 'OK   ';
	} elseif ( false === $good ) {
		$mark = 'FAIL ';
		$ok   = false;
	}
	$out[] = $mark . str_pad( $label, 42 ) . $value;
};

$out[] = '=== Fluent Forms replacement preflight ===';

$line( 'Plugin version', defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'not active', defined( 'GSWP_VERSION' ) && version_compare( GSWP_VERSION, '2.23.0', '>=' ) );
$line( 'Provider registry loaded', class_exists( 'GSWP_Form_Provider_Registry' ) ? 'yes' : 'no', class_exists( 'GSWP_Form_Provider_Registry' ) );
$line( 'FF provider loaded', class_exists( 'GSWP_Provider_Fluent_Forms' ) ? 'yes' : 'no', class_exists( 'GSWP_Provider_Fluent_Forms' ) );

if ( ! class_exists( 'GSWP_Provider_Fluent_Forms' ) ) {
	$out[] = '';
	$out[] = 'STOP: plugin not active or older than 2.23.0.';
	echo implode( "\n", $out ) . "\n";
	return;
}

// ---------------------------------------------------------------------------
// What actually exists. This block settles is_active(): the provider must not
// rest on an unqualified class_exists() against a namespaced class, which is
// the Phase 45 defect verbatim.
// ---------------------------------------------------------------------------
$out[] = '';
$out[] = '--- FLUENT FORMS DETECTION SURFACE (report verbatim) ---';

foreach ( array( 'FLUENTFORM', 'FLUENTFORM_VERSION', 'FLUENTFORMPRO', 'FLUENTFORMPRO_VERSION' ) as $const ) {
	$line( '  constant ' . $const, defined( $const ) ? ( is_scalar( constant( $const ) ) ? (string) constant( $const ) : 'defined' ) : 'not defined', null );
}

foreach ( array( 'wpFluentForm', 'wpFluent', 'fluentFormApi' ) as $fn ) {
	$line( '  function ' . $fn . '()', function_exists( $fn ) ? 'exists' : 'missing', null );
}

foreach (
	array(
		'\FluentForm\App\Helpers\Helper',
		'\FluentForm\App\Models\Form',
		'\FluentForm\App\Models\Submission',
		'\FluentForm\App\Services\Form\FormValidationService',
	) as $class
) {
	$line( '  class ' . $class, class_exists( $class ) ? 'exists' : 'missing', null );
}

// Helper methods the provider calls for submission meta.
if ( class_exists( '\FluentForm\App\Helpers\Helper' ) ) {
	foreach ( array( 'setSubmissionMeta', 'getSubmissionMeta' ) as $method ) {
		$line( '  Helper::' . $method . '()', method_exists( '\FluentForm\App\Helpers\Helper', $method ) ? 'exists' : 'MISSING', method_exists( '\FluentForm\App\Helpers\Helper', $method ) );
	}
}

// Tables.
global $wpdb;
$out[] = '';
$out[] = '--- TABLES ---';
foreach ( array( 'fluentform_forms', 'fluentform_form_meta', 'fluentform_submissions', 'fluentform_submission_meta', 'fluentform_transactions' ) as $suffix ) {
	$table = $wpdb->prefix . $suffix;
	$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB
	$line( '  ' . $suffix, $found === $table ? 'present' : 'ABSENT', null );
}

// Columns on the forms table — has_payment is the authoritative payment signal.
$forms_table = $wpdb->prefix . 'fluentform_forms';
if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $forms_table ) ) === $forms_table ) {
	$columns = $wpdb->get_col( "SHOW COLUMNS FROM {$forms_table}" ); // phpcs:ignore WordPress.DB
	$out[]   = '';
	$out[]   = '  fluentform_forms columns: ' . implode( ', ', (array) $columns );
	$line( '  has_payment column', in_array( 'has_payment', (array) $columns, true ) ? 'present' : 'ABSENT (field scan will be used)', null );
	$line( '  form_fields column', in_array( 'form_fields', (array) $columns, true ) ? 'present' : 'ABSENT', in_array( 'form_fields', (array) $columns, true ) );
}

// ---------------------------------------------------------------------------
// Provider state.
// ---------------------------------------------------------------------------
$provider = GSWP_Form_Provider_Registry::get( 'fluent-forms' );

$out[] = '';
$out[] = '--- PROVIDER STATE ---';
$line( 'Provider registered', $provider ? 'yes' : 'no', (bool) $provider );
$line( 'Provider reports active', ( $provider && $provider->is_active() ) ? 'yes' : 'no', $provider && $provider->is_active() );
$line( 'reCAPTCHA site key configured', '' !== GSWP_Recaptcha_Loader::site_key() ? 'yes' : 'NO', '' !== GSWP_Recaptcha_Loader::site_key() );
$line( 'Key type', get_option( 'gswp_key_type', 'classic' ), null );
$line( 'Form protection master switch', GSWP_Form_Provider_Registry::enabled() ? 'enabled' : 'DISABLED', null );
$line( 'FF replacement', GSWP_Form_Provider_Registry::is_on( 'fluent-forms' ) ? 'ON' : 'off (expected on first release)', null );
$line( 'Auto-enabled on upgrade', GSWP_Form_Provider_Registry::migrates_by_default( 'fluent-forms' ) ? 'yes' : 'no (expected)', null );

if ( $provider && $provider->is_active() ) {
	$forms = $provider->forms();
	$line( 'Fluent Forms found', (string) count( $forms ), count( $forms ) > 0 );

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
	$line( '  of which are ineligible', (string) $inel, null );
}

$out[] = '';
$out[] = $ok ? 'PREFLIGHT PASSED — continue to chunk 21.' : 'PREFLIGHT FAILED — fix the FAIL lines before continuing.';
$out[] = '';
$out[] = 'Report the whole block above verbatim, including the DETECTION SURFACE';
$out[] = 'and TABLES sections — those settle bindings, not just this run.';

echo implode( "\n", $out ) . "\n";
