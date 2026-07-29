<?php
/**
 * Fluent Forms replacement verification — chunk 23: native captcha (v2.23.0)
 *
 * Settles what Fluent Forms' own captcha is and where it is stored.
 *
 * Only one binding here is confirmed: `_fluentform_reCaptcha_details` was
 * verified against a live install during this project's Smart Key Scavenger
 * work. Everything else — the version key inside it, and the hCaptcha and
 * Turnstile option names — is inferred, and getting them wrong has a specific
 * consequence: a form running a visible challenge would be reported as one we
 * can replace, and we would take it over.
 *
 * This is also where the provider interface gained a fifth captcha state.
 * Fluent Forms ships reCAPTCHA, hCaptcha AND Turnstile, and 'off' / 'v3' / 'v2'
 * / 'unknown' could not express the latter two: 'off' is a lie, 'v2' misnames
 * the product to an operator who then hunts for reCAPTCHA settings that do not
 * exist, and 'unknown' would leave the form eligible so we would take over a
 * form already running Turnstile. 'other' is the honest answer and it makes the
 * form ineligible.
 *
 * READ-ONLY, and deliberately so: it reads option rows straight from $wpdb,
 * never through get_option(), so nothing this plugin does can colour what it
 * reports about another plugin. It writes nothing. Secrets are masked.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo "=== RUN CONTEXT ===\n";
echo '  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ) . "\n";
echo '  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ) . "\n";
echo '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ) . "\n\n";

if ( ! class_exists( 'GSWP_Provider_Fluent_Forms' ) ) {
	echo "STOP: plugin not active or older than 2.23.0.\n";
	return;
}

global $wpdb;

/**
 * Mask anything that looks like a credential.
 *
 * A site key is not secret, but a secret key shares this option and telling
 * them apart by name is exactly the kind of assumption this suite exists to
 * avoid. Everything long enough to be a key is masked.
 *
 * @param mixed $value Raw value.
 * @return string Printable, masked.
 */
function gswp_ff_mask( $value ) {
	if ( is_array( $value ) ) {
		return 'array(' . count( $value ) . ')';
	}
	if ( is_bool( $value ) ) {
		return $value ? 'true' : 'false';
	}

	$value = (string) $value;

	if ( strlen( $value ) > 12 ) {
		return substr( $value, 0, 6 ) . str_repeat( '.', 6 ) . ' (len ' . strlen( $value ) . ')';
	}

	return $value;
}

// ---------------------------------------------------------------------------
// Every Fluent Forms option row. Names in full, values masked. Reporting an
// unrecognised finding honestly is the point — the alternative is the silent
// skip that made GF detection report "unknown" for a plugin configured all
// along.
// ---------------------------------------------------------------------------
echo "=== FLUENT FORMS OPTION ROWS (names verbatim, values masked) ===\n\n";

$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
	"SELECT option_name, option_value FROM {$wpdb->options}
	 WHERE option_name LIKE '%fluentform%' OR option_name LIKE '%fluent_form%'
	 ORDER BY option_name ASC",
	ARRAY_A
);

if ( empty( $rows ) ) {
	echo "  none found.\n";
} else {
	foreach ( $rows as $row ) {
		$name  = $row['option_name'];
		$value = maybe_unserialize( $row['option_value'] );

		if ( is_string( $value ) ) {
			$decoded = json_decode( $value, true );
			if ( is_array( $decoded ) ) {
				$value = $decoded;
			}
		}

		echo '  ' . $name . "\n";

		if ( is_array( $value ) ) {
			foreach ( $value as $k => $v ) {
				echo '      ' . str_pad( (string) $k, 26 ) . gswp_ff_mask( $v ) . "\n";
			}
		} else {
			echo '      (scalar) ' . gswp_ff_mask( $value ) . "\n";
		}
	}
}

// ---------------------------------------------------------------------------
// Which of the provider's candidate option names actually hit.
// ---------------------------------------------------------------------------
echo "\n=== CANDIDATE OPTION NAMES ===\n\n";

$candidates = array(
	'_fluentform_reCaptcha_details' => 'reCAPTCHA (VERIFIED name)',
	'_fluentform_recaptcha_details' => 'reCAPTCHA (lowercase variant)',
	'fluentform_reCaptcha_details'  => 'reCAPTCHA (unprefixed variant)',
	'_fluentform_hCaptcha_details'  => 'hCaptcha (INFERRED)',
	'_fluentform_hcaptcha_details'  => 'hCaptcha (INFERRED, lowercase)',
	'_fluentform_turnstile_details' => 'Turnstile (INFERRED)',
	'fluentform_global_modules_status' => 'module switches',
	'fluentform_settings'           => 'legacy global settings',
);

foreach ( $candidates as $option => $note ) {
	$exists = $wpdb->get_var( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ) ); // phpcs:ignore WordPress.DB
	printf( "  %-36s %-10s %s\n", $option, $exists ? 'PRESENT' : 'absent', $note );
}

// ---------------------------------------------------------------------------
// Per-form captcha fields, and what the provider concludes.
// ---------------------------------------------------------------------------
echo "\n=== PER-FORM CAPTCHA FIELDS AND RESOLVED STATE ===\n\n";

$provider = GSWP_Form_Provider_Registry::get( 'fluent-forms' );

if ( ! $provider || ! $provider->is_active() ) {
	echo "  Fluent Forms is not active.\n";
} else {
	$forms_table = $wpdb->prefix . 'fluentform_forms';

	printf( "  %-5s %-30s %-22s %-10s %s\n", 'ID', 'TITLE', 'CAPTCHA FIELDS', 'STATE', 'ELIGIBLE' );
	echo '  ' . str_repeat( '-', 92 ) . "\n";

	foreach ( $provider->forms() as $form_id => $title ) {
		$json = $wpdb->get_var( $wpdb->prepare( "SELECT form_fields FROM {$forms_table} WHERE id = %d", (int) $form_id ) ); // phpcs:ignore WordPress.DB

		// Raw string search rather than a structured walk: this chunk must be
		// able to report a captcha the provider's own parser missed.
		$found = array();
		foreach ( array( 'recaptcha', 'hcaptcha', 'turnstile' ) as $needle ) {
			if ( is_string( $json ) && false !== stripos( $json, '"' . $needle . '"' ) ) {
				$found[] = $needle;
			}
		}

		printf(
			"  %-5s %-30s %-22s %-10s %s\n",
			$form_id,
			substr( (string) $title, 0, 29 ),
			empty( $found ) ? '—' : implode( ',', $found ),
			$provider->native_captcha_state( $form_id ),
			$provider->form_is_eligible( $form_id ) ? 'yes' : 'NO'
		);
	}
}

echo "\n=== WHAT TO CHECK ===\n";
echo "  1. Any form whose CAPTCHA FIELDS column is non-empty must NOT be\n";
echo "     eligible. If one is, the state resolver missed it and the provider\n";
echo "     would take over a form running a visible challenge.\n";
echo "  2. Any form showing state 'unknown' while the option rows above plainly\n";
echo "     show a configured captcha means the version key is misread. Report\n";
echo "     the option block; the fix is the gswp_ff_native_captcha_options\n";
echo "     filter, not a release.\n";
echo "  3. The provider never returns 'off'. Proving a captcha is absent means\n";
echo "     trusting that our list of option names is complete, and it is not\n";
echo "     confirmed — so a site with no captcha configured reads 'unknown'\n";
echo "     rather than 'off'. That is noisier but it is the honest direction:\n";
echo "     'unknown' can never let the settings screen tell you another\n";
echo "     plugin's captcha is switched off when it is running. Eligibility is\n";
echo "     unaffected either way; only the column text differs.\n";

echo "\nReport the whole block above verbatim.\n";
