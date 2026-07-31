<?php
/**
 * Fluent Forms replacement verification — chunk 22: submission shape (v2.23.2)
 *
 * THE CRITICAL ONE. It settles the two Fluent Forms unknowns that can each
 * break every form on the site, and it settles them without needing a real
 * submission to be judged.
 *
 * -------------------------------------------------------------------------
 * QUESTION 1 — where does the token arrive?
 *
 * VERIFIED against Fluent Forms 6.2.9 source (2.23.2): $formData at the
 * validation filter is filtered down to REGISTERED fields plus a fixed
 * allow-list (Helper::getWhiteListedFields()). An unregistered,
 * unwhitelisted key never survives. That is why register_hooks() now adds
 * gswp_ff_token to that allow-list via fluentform/white_listed_fields
 * (whitelist_token_field()) — transport 1 (reading $formData directly) is
 * only genuinely live BECAUSE of that registration, not despite skipping it.
 *
 * A prior version of this provider believed transport 1 already worked
 * without registering anything, reasoning from two allow-listed keys
 * (_wp_http_referer, the per-form nonce) observed in a real capture. Those
 * are the two NAMED exceptions on the allow-list, not evidence that
 * unregistered keys survive in general — transport 1 was dead from the day
 * it was written until the whitelist filter was added. This chunk now
 * checks the whitelist registration directly, not just the resolver's
 * synthetic behaviour, because "the resolver can parse this shape" and
 * "Fluent Forms will actually hand it this shape" are different claims and
 * conflating them once already produced a false "settled" in this project's
 * own state tracker.
 *
 * -------------------------------------------------------------------------
 * QUESTION 2 — can the visitor SEE a rejection?
 *
 * VERIFIED (2.23.2): Fluent Forms' inline error renderer falls back to the
 * .ff-errors-in-stack container for any errors key that resolves to no DOM
 * node, and that fallback fires under BOTH errorMessagePlacement settings
 * (assets/js/form-submission.js). reject() now deliberately uses such a
 * key — GSWP_Provider_Fluent_Forms::ERROR_KEY — instead of borrowing a real
 * field. The one key that is DANGEROUS to use is TOKEN_FIELD itself: it
 * resolves to our own hidden input, and an error appended there renders
 * inside an <input>, which is nothing. This chunk asserts the resolved key
 * is never TOKEN_FIELD, for every form and under any gswp_ff_error_field
 * filter override.
 *
 * Read-only. Makes no submission, creates no entry, calls no network.
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

$provider = GSWP_Form_Provider_Registry::get( 'fluent-forms' );
if ( ! $provider || ! $provider->is_active() ) {
	echo "STOP: Fluent Forms is not active on this site.\n";
	return;
}

$reflect = new ReflectionClass( $provider );

$call = function ( $method, $args ) use ( $provider, $reflect ) {
	if ( ! $reflect->hasMethod( $method ) ) {
		return null;
	}
	$m = $reflect->getMethod( $method );
	$m->setAccessible( true );

	return $m->invokeArgs( $provider, $args );
};

// ---------------------------------------------------------------------------
// QUESTION 1a — is TOKEN_FIELD actually on Fluent Forms' allow-list?
// This is the 2.23.2 fix. Exercised directly rather than inferred from the
// resolver, because the resolver alone cannot tell you whether Fluent Forms
// was ever asked to keep the field.
// ---------------------------------------------------------------------------
echo "=== TOKEN FIELD WHITELIST REGISTRATION (2.23.2) ===\n\n";

if ( ! $reflect->hasMethod( 'whitelist_token_field' ) ) {
	echo "  This provider version has no whitelist_token_field() method — on an\n";
	echo "  older release, transport 1 is not registered and this section does\n";
	echo "  not apply. Report the plugin version above.\n\n";
} else {
	printf( "  %-5s %-34s %s\n", 'ID', 'TITLE', 'gswp_ff_token WHITELISTED?' );
	echo '  ' . str_repeat( '-', 70 ) . "\n";

	foreach ( $provider->forms() as $form_id => $title ) {
		$whitelist = (array) $call( 'whitelist_token_field', array( array(), $form_id ) );
		$present   = in_array( GSWP_Provider_Fluent_Forms::TOKEN_FIELD, $whitelist, true );

		printf(
			"  %-5s %-34s %s\n",
			$form_id,
			substr( (string) $title, 0, 33 ),
			$present ? 'yes' : ( $provider->form_is_eligible( $form_id ) ? 'NO — unexpected on an eligible form' : 'no (not eligible, expected)' )
		);
	}

	echo "\n  Every ELIGIBLE form should say 'yes'. A 'NO' on an eligible form means\n";
	echo "  transport 1 is dead again on this Fluent Forms version and needs\n";
	echo "  re-diagnosing before the provider is trusted with an account or\n";
	echo "  payment form.\n";
}

// ---------------------------------------------------------------------------
// QUESTION 1b — token transport, exercised against each envelope in turn.
// This proves the RESOLVER handles each shape. It does not by itself prove
// which shape Fluent Forms actually sends — see "HOW TO CAPTURE" below for
// that, and see the whitelist section above for why transport 1 should now
// be the one that wins on a real submission.
// ---------------------------------------------------------------------------
echo "\n=== TOKEN TRANSPORT RESOLUTION (synthetic) ===\n\n";

$sentinel = 'GSWP-SENTINEL-TOKEN-' . wp_generate_password( 12, false );
$saved    = $_POST; // phpcs:ignore WordPress.Security.NonceVerification

$cases = array(
	'1. parsed $formData'      => array(
		'post' => array(),
		'data' => array( 'gswp_ff_token' => $sentinel ),
	),
	'2. serialised "data" env' => array(
		'post' => array( 'data' => 'foo=bar&gswp_ff_token=' . rawurlencode( $sentinel ) . '&baz=1' ),
		'data' => array(),
	),
	'3. serialised "formData"' => array(
		'post' => array( 'formData' => 'gswp_ff_token=' . rawurlencode( $sentinel ) ),
		'data' => array(),
	),
	'4. plain $_POST'          => array(
		'post' => array( 'gswp_ff_token' => $sentinel ),
		'data' => array(),
	),
	'5. nothing anywhere'      => array(
		'post' => array(),
		'data' => array(),
	),
);

foreach ( $cases as $label => $case ) {
	$_POST  = $case['post']; // phpcs:ignore WordPress.Security.NonceVerification
	$result = $call( 'submitted_token', array( $case['data'] ) );

	$verdict = ( $result === $sentinel )
		? 'RECOVERED'
		: ( '' === $result ? 'empty (correct for case 5)' : 'UNEXPECTED: ' . $result );

	printf( "  %-30s %s\n", $label, $verdict );
}

$_POST = $saved; // phpcs:ignore WordPress.Security.NonceVerification

echo "\n  All of 1-4 should say RECOVERED and 5 should say empty. This is the\n";
echo "  resolver's own correctness, independent of whether Fluent Forms sends\n";
echo "  shape 1, 2, 3, or a mix. The 'HOW TO CAPTURE' section below is what\n";
echo "  determines which one actually fires in practice — do not treat this\n";
echo "  section alone as proof of live behaviour.\n";

// ---------------------------------------------------------------------------
// The live shape. Only meaningful when this file is executed during an actual
// submission (see the instructions at the foot of this chunk).
// ---------------------------------------------------------------------------
echo "\n=== LIVE REQUEST SHAPE ===\n\n";

// phpcs:ignore WordPress.Security.NonceVerification
if ( empty( $_POST ) ) {
	echo "  No POST data in this request — this chunk was run from the CLI or a\n";
	echo "  GET. That is fine for everything above. To capture the REAL shape,\n";
	echo "  follow 'HOW TO CAPTURE A REAL SUBMISSION' below.\n";
} else {
	// phpcs:ignore WordPress.Security.NonceVerification
	foreach ( array_keys( $_POST ) as $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification
		$value = $_POST[ $key ];
		$shape = is_array( $value ) ? 'array(' . count( $value ) . ')' : 'string(' . strlen( (string) $value ) . ')';
		printf( "  %-24s %s\n", sanitize_key( $key ), $shape );

		// Print the envelope's KEYS only. The values are somebody's submission.
		if ( is_string( $value ) && false !== strpos( $value, '=' ) && strlen( $value ) > 40 ) {
			$parsed = array();
			parse_str( $value, $parsed );
			if ( count( $parsed ) > 1 ) {
				echo '      parses to keys: ' . implode( ', ', array_map( 'sanitize_key', array_keys( $parsed ) ) ) . "\n";
				echo '      carries our token: ' . ( isset( $parsed['gswp_ff_token'] ) ? 'YES' : 'no' ) . "\n";
			}
		}
	}
}

// ---------------------------------------------------------------------------
// QUESTION 2 — where a rejection message would be displayed, and whether the
// deliberately-unresolvable ERROR_KEY has been kept unresolvable.
// ---------------------------------------------------------------------------
echo "\n=== REJECTION DELIVERY (per form) ===\n\n";

if ( ! $reflect->hasConstant( 'ERROR_KEY' ) ) {
	echo "  This provider version has no ERROR_KEY constant — it is attaching\n";
	echo "  rejection messages to a real form field instead (pre-2.23.2\n";
	echo "  behaviour). See error_field_for() in the provider source.\n\n";
} else {
	$error_key_default = GSWP_Provider_Fluent_Forms::ERROR_KEY;
	$token_field        = GSWP_Provider_Fluent_Forms::TOKEN_FIELD;

	printf( "  %-5s %-34s %-24s %-10s %s\n", 'ID', 'TITLE', 'RESOLVED ERROR KEY', 'PLACEMENT', 'VERDICT' );
	echo '  ' . str_repeat( '-', 100 ) . "\n";

	global $wpdb;
	$meta_table = $wpdb->prefix . 'fluentform_form_meta';

	$dangerous = 0;

	foreach ( $provider->forms() as $form_id => $title ) {
		if ( ! $provider->form_is_eligible( $form_id ) ) {
			continue;
		}

		$key = (string) apply_filters( 'gswp_ff_error_field', $error_key_default, (int) $form_id );

		// reject() itself refuses TOKEN_FIELD even if a filter tries to set it,
		// falling back to ERROR_KEY — but a filter returning it here is still
		// worth flagging, because it means a site override is fighting the
		// provider's own safety net rather than agreeing with it.
		$effective = ( '' === $key || $token_field === $key ) ? $error_key_default : $key;
		$is_bad    = ( $token_field === $key );

		if ( $is_bad ) {
			++$dangerous;
		}

		$settings_json = $wpdb->get_var(
			$wpdb->prepare( "SELECT value FROM {$meta_table} WHERE form_id = %d AND meta_key = 'formSettings'", (int) $form_id ) // phpcs:ignore WordPress.DB
		);
		$settings      = is_string( $settings_json ) ? json_decode( $settings_json, true ) : null;
		$placement     = is_array( $settings ) ? (string) ( $settings['layout']['errorMessagePlacement'] ?? 'inline' ) : 'inline (default)';

		printf(
			"  %-5s %-34s %-24s %-10s %s\n",
			$form_id,
			substr( (string) $title, 0, 33 ),
			$effective,
			$placement,
			$is_bad ? 'DANGEROUS — filter returned TOKEN_FIELD, reject() will override it' : 'ok'
		);
	}

	if ( $dangerous > 0 ) {
		echo "\n  {$dangerous} form(s) have a gswp_ff_error_field filter returning\n";
		echo "  TOKEN_FIELD. reject() refuses that value and substitutes ERROR_KEY,\n";
		echo "  so nothing is currently broken — but the filter itself should be\n";
		echo "  corrected, because whatever set it believed TOKEN_FIELD was a safe\n";
		echo "  place to display a message, and it is the one place that renders\n";
		echo "  nothing.\n";
	} else {
		echo "\n  No form resolves to TOKEN_FIELD. Every rejection is delivered to a\n";
		echo "  key that matches no form field, which Fluent Forms falls back to\n";
		echo "  rendering in its error-stack container under both placement\n";
		echo "  settings shown above.\n";
	}
}

// ---------------------------------------------------------------------------
echo "\n=== HOW TO CAPTURE A REAL SUBMISSION ===\n";
echo "  The sections above prove the resolver handles each envelope and that\n";
echo "  the rejection key is safe. They do NOT prove which envelope Fluent\n";
echo "  Forms actually uses on THIS site, or that a rejection is actually\n";
echo "  visible on screen. Only a real submission in a real browser proves\n";
echo "  those.\n";
echo "\n";
echo "  *** SWITCH THE PROVIDER ON FIRST. ***\n";
echo "\n";
echo "  Settings -> Google Security -> Form Protection -> Fluent Forms.\n";
echo "\n";
echo "  With the provider OFF no token field is rendered into the form at all,\n";
echo "  so the capture below will correctly report 'token in formData: no' and\n";
echo "  settle nothing about our field.\n";
echo "\n";
echo "  Provider state right now: " . ( GSWP_Form_Provider_Registry::is_on( 'fluent-forms' ) ? 'ON — good, capture is meaningful' : 'OFF — turn it on before capturing' ) . "\n";
echo "\n";
echo "  STEP 1 — confirm transport 1. Add this to a mu-plugin, submit one\n";
echo "  non-payment, non-account form in a browser, read the log, and REMOVE\n";
echo "  IT AGAIN:\n\n";
echo "    add_filter( 'fluentform/validation_errors', function ( \$e, \$d, \$f, \$fl ) {\n";
echo "        error_log( 'GSWP POST keys: ' . implode( ',', array_keys( \$_POST ) ) );\n";
echo "        error_log( 'GSWP formData keys: ' . implode( ',', array_keys( (array) \$d ) ) );\n";
echo "        error_log( 'GSWP token in formData: ' . ( isset( \$d['gswp_ff_token'] ) ? 'yes' : 'no' ) );\n";
echo "        return \$e;\n";
echo "    }, 1, 4 );\n\n";
echo "  Expected on 2.23.2, with the provider ON:\n";
echo "    GSWP formData keys  : ...,gswp_ff_token,... (our field survived)\n";
echo "    GSWP token in formData: yes\n";
echo "\n";
echo "  A 'no' on the last line now means the whitelist registration checked\n";
echo "  above (TOKEN FIELD WHITELIST REGISTRATION) did not take effect on this\n";
echo "  request — report the whitelist table results alongside this. The\n";
echo "  submission is still scored either way, because transport 2 reads the\n";
echo "  raw envelope as a backstop — this is a finding to report, not an\n";
echo "  outage.\n";
echo "\n";
echo "  STEP 2 — confirm a rejection is VISIBLE. On a form you do not mind\n";
echo "  breaking temporarily, force a rejection (block\n";
echo "  www.google.com/recaptcha in the browser network tab, or submit twice\n";
echo "  quickly so the second token is spent) and confirm the message actually\n";
echo "  appears on screen — not just that the request returns an error. Do\n";
echo "  this once with a form set to 'inline' placement and once with\n";
echo "  'stackToBottom' if the site uses both (see the PLACEMENT column above).\n";
echo "  If a form uses a non-standard payment method whose JS renders its own\n";
echo "  error box (PayPal Inline is the known case — it reads\n";
echo "  Object.values(errors)[0] into its own element, ignoring the key), test\n";
echo "  that one separately: the message must still be the FIRST value FluentForms'\n";
echo "  errors object.\n";
echo "\n";
echo "  Then check the coverage table: the form should show a rejection reason\n";
echo "  matching what you triggered, and no coverage gap in the log.\n";

echo "\nReport the whole block above verbatim.\n";
