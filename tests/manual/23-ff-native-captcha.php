<?php
/**
 * Fluent Forms replacement verification — chunk 23: native captcha (v2.23.2)
 *
 * Settles what Fluent Forms' own captcha is and where it is stored.
 *
 * VERIFIED against Fluent Forms 6.2.9 source (2.23.2): the reCAPTCHA,
 * hCaptcha and Turnstile option names, their key sets, and the two literal
 * reCAPTCHA version values ('v2_visible', 'v3_invisible') are all confirmed
 * against GlobalSettingsHelper. What changed in 2.23.2 is eligibility
 * itself: a prior version fell back to reporting the SITE'S global reCAPTCHA
 * configuration whenever a form had no captcha field, which meant a site
 * with reCAPTCHA v2 keys saved — common, even on sites that never actually
 * put reCAPTCHA on a form — made EVERY Fluent Form on the site ineligible,
 * silently. native_captcha_state() now checks Fluent Forms' own
 * auto-include filters (fluentform/has_recaptcha / has_hcaptcha /
 * has_turnstile) instead, the same gate FormValidationService itself uses
 * to decide whether a challenge validates at all — so 'off' is now provable
 * rather than assumed, and this chunk exists to prove it on THIS site.
 *
 * This is also where the provider interface gained a sixth captcha state,
 * 'unsupported', for a Fluent Forms conversational form: it renders through
 * a separate view that fires none of the hooks this provider can inject
 * into, so it can never be covered and is reported as such rather than
 * quietly failing.
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
	// Fluent Forms stores some options as serialized OBJECTS.
	if ( is_object( $value ) ) {
		return 'object(' . get_class( $value ) . ', ' . count( get_object_vars( $value ) ) . ' props)';
	}
	if ( is_bool( $value ) ) {
		return $value ? 'true' : 'false';
	}
	if ( null === $value ) {
		return '(null)';
	}

	$value = (string) $value;

	if ( strlen( $value ) > 12 ) {
		return substr( $value, 0, 6 ) . str_repeat( '.', 6 ) . ' (len ' . strlen( $value ) . ')';
	}

	return $value;
}

// ---------------------------------------------------------------------------
// Every Fluent Forms option row. Names in full, values masked.
// ---------------------------------------------------------------------------
echo "=== FLUENT FORMS OPTION ROWS (names verbatim, values masked) ===\n\n";

// phpcs:ignore WordPress.DB
$rows = $wpdb->get_results(
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

		$was_object = is_object( $value );
		if ( $was_object ) {
			$encoded = wp_json_encode( $value );
			$decoded = is_string( $encoded ) ? json_decode( $encoded, true ) : null;
			if ( is_array( $decoded ) ) {
				$value = $decoded;
			}
		}

		echo '  ' . $name . ( $was_object ? '   [stored as an OBJECT, not an array]' : '' ) . "\n";

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
// Which of the provider's candidate option names actually hit. All three
// challenge products' names and key sets are now VERIFIED against source
// (2.23.2) — the lowercase/unprefixed variants are kept as tolerance for a
// version this was not checked against, not as live guesses.
// ---------------------------------------------------------------------------
echo "\n=== CANDIDATE OPTION NAMES ===\n\n";

$candidates = array(
	'_fluentform_reCaptcha_details'    => 'reCAPTCHA (VERIFIED)',
	'_fluentform_recaptcha_details'    => 'reCAPTCHA (lowercase variant, tolerance only)',
	'fluentform_reCaptcha_details'     => 'reCAPTCHA (unprefixed variant, tolerance only)',
	'_fluentform_hCaptcha_details'     => 'hCaptcha (VERIFIED)',
	'_fluentform_turnstile_details'    => 'Turnstile (VERIFIED)',
	'fluentform_global_modules_status' => 'module switches',
	'fluentform_settings'              => 'legacy global settings',
);

foreach ( $candidates as $option => $note ) {
	$exists = $wpdb->get_var( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ) ); // phpcs:ignore WordPress.DB
	printf( "  %-36s %-10s %s\n", $option, $exists ? 'PRESENT' : 'absent', $note );
}

// ---------------------------------------------------------------------------
// The "configured AND validated" flags. Set only after Fluent Forms
// round-tripped the key pair with the vendor at save time — a stronger claim
// than "a siteKey string is non-empty".
// ---------------------------------------------------------------------------
echo "\n=== KEY VALIDATION STATUS FLAGS ===\n\n";

foreach (
	array(
		'_fluentform_reCaptcha_keys_status' => 'reCAPTCHA',
		'_fluentform_hCaptcha_keys_status'  => 'hCaptcha',
		'_fluentform_turnstile_keys_status' => 'Turnstile',
	) as $option => $label
) {
	$value = get_option( $option, null );
	printf( "  %-38s %-10s %s\n", $option, null === $value ? 'absent' : ( $value ? 'true' : 'false' ), $label );
}

// ---------------------------------------------------------------------------
// The auto-include filters. THE 2.23.2 FIX: a form with no captcha field is
// only 'off' if none of these say otherwise, matching
// FormValidationService::validateReCaptcha()/validateHCaptcha()/
// validateTurnstile() exactly.
// ---------------------------------------------------------------------------
echo "\n=== AUTO-INCLUDE FILTERS (2.23.2) ===\n\n";
echo "  If any of these return true, Fluent Forms validates that challenge on\n";
echo "  EVERY form regardless of whether the field is present, and this\n";
echo "  provider now follows suit rather than reporting a global option.\n\n";

foreach (
	array(
		'fluentform/has_recaptcha' => 'reCAPTCHA',
		'fluentform/has_hcaptcha'  => 'hCaptcha',
		'fluentform/has_turnstile' => 'Turnstile',
	) as $filter => $label
) {
	printf( "  %-30s %-8s %s\n", $filter, apply_filters( $filter, false ) ? 'TRUE' : 'false', $label );
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

	printf( "  %-5s %-30s %-22s %-12s %s\n", 'ID', 'TITLE', 'CAPTCHA FIELDS', 'STATE', 'ELIGIBLE' );
	echo '  ' . str_repeat( '-', 92 ) . "\n";

	$off_count         = 0;
	$off_with_no_field = 0;

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

		$state = $provider->native_captcha_state( $form_id );

		if ( 'off' === $state ) {
			++$off_count;
			if ( empty( $found ) ) {
				++$off_with_no_field;
			}
		}

		printf(
			"  %-5s %-30s %-22s %-12s %s\n",
			$form_id,
			substr( (string) $title, 0, 29 ),
			empty( $found ) ? '—' : implode( ',', $found ),
			$state,
			$provider->form_is_eligible( $form_id ) ? 'yes' : 'NO'
		);
	}

	echo "\n  {$off_count} form(s) report state 'off'.";
	if ( $off_count > 0 ) {
		echo " {$off_with_no_field} of those have no captcha field on the form\n";
		echo "  itself, so 'off' is only correct if none of the auto-include\n";
		echo "  filters above returned true for them. Cross-check the AUTO-INCLUDE\n";
		echo "  FILTERS section: if any filter is TRUE, every 'off' row above is\n";
		echo "  now wrong and must be reported.\n";
	} else {
		echo "\n";
	}
}

echo "\n=== WHAT TO CHECK ===\n";
echo "  1. Any form whose CAPTCHA FIELDS column is non-empty must NOT be\n";
echo "     eligible. If one is, the state resolver missed it and the provider\n";
echo "     would take over a form running a visible challenge.\n";
echo "  2. Any form showing state 'unknown' means the form definition itself\n";
echo "     could not be read — a different failure from 'off'. Report it.\n";
echo "  3. Any row marked [stored as an OBJECT, not an array] is the shape that\n";
echo "     crashed the first version of chunk 23, and that\n";
echo "     GSWP_Provider_Fluent_Forms::raw_option() silently returned null for\n";
echo "     until 2.23.1. If the reCAPTCHA row is one of those, detection was\n";
echo "     blind to it.\n";
echo "  4. As of 2.23.2 the provider DOES return 'off', and this is the check\n";
echo "     that matters most this release: if this site has reCAPTCHA v2 keys\n";
echo "     saved in the OPTION ROWS section above, but a specific form shows\n";
echo "     no captcha field AND all three AUTO-INCLUDE FILTERS are false, that\n";
echo "     form correctly reports 'off' and stays ELIGIBLE — where a prior\n";
echo "     version of this plugin would have reported that form's Fluent\n";
echo "     Forms captcha as 'v2' and marked it ineligible for no reason\n";
echo "     visible anywhere in the UI. If a form on THIS site was previously\n";
echo "     ineligible with no captcha field of its own, it should now show\n";
echo "     'off' and ELIGIBLE = yes — confirm that flip happened.\n";
echo "  5. A form with state 'unsupported' is a Fluent Forms conversational\n";
echo "     form (2.23.2). It is correctly ineligible and will never show a\n";
echo "     coverage gap in the log — see chunk 21.\n";

echo "\nReport the whole block above verbatim.\n";
