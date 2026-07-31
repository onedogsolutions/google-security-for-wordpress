<?php
/**
 * Fluent Forms replacement verification — chunk 22: submission shape (v2.23.0)
 *
 * THE CRITICAL ONE. It settles the two Fluent Forms unknowns that can each
 * break every form on the site, and it settles them without needing a real
 * submission to be judged.
 *
 * -------------------------------------------------------------------------
 * QUESTION 1 — where does the token arrive?
 *
 * Gravity Forms posts natively, so $_POST['gswp_gf_token'] is simply there.
 * Fluent Forms submits over AJAX and serialises the form into a single request
 * parameter, so $_POST['gswp_ff_token'] is probably EMPTY and the token is
 * inside that envelope.
 *
 * If the provider read only $_POST it would see no token on every submission of
 * every form. On a payment or account form that fails CLOSED — permanently, for
 * every visitor. That is the 2.22.0 defect again, and it is why this chunk
 * exists before the provider is switched on anywhere.
 *
 * The provider therefore tries three transports. This chunk reports which one
 * actually carried it.
 *
 * -------------------------------------------------------------------------
 * QUESTION 2 — can the visitor SEE a rejection?
 *
 * Fluent Forms attaches validation errors to fields. Our token field is not one
 * of its registered fields, so an error keyed to it may be delivered to the
 * browser and then dropped for want of a DOM node to attach it to. The visitor
 * sees the submit button spin and stop, with nothing on screen.
 *
 * That symptom already cost this project a debugging cycle in Phase 48. This
 * plugin must have no branch that hangs a submission. So: the provider attaches
 * its message to a real field, and this chunk prints which field it picked, per
 * form, so the choice can be eyeballed before anyone relies on it.
 * -------------------------------------------------------------------------
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
// QUESTION 1 — token transport, exercised against each envelope in turn.
// ---------------------------------------------------------------------------
echo "=== TOKEN TRANSPORT ===\n\n";

$sentinel = 'GSWP-SENTINEL-TOKEN-' . wp_generate_password( 12, false );
$saved    = $_POST; // phpcs:ignore WordPress.Security.NonceVerification

$cases = array(
	'1. parsed $formData'         => array(
		'post' => array(),
		'data' => array( 'gswp_ff_token' => $sentinel ),
	),
	'2. serialised "data" env'    => array(
		'post' => array( 'data' => 'foo=bar&gswp_ff_token=' . rawurlencode( $sentinel ) . '&baz=1' ),
		'data' => array(),
	),
	'3. serialised "formData"'    => array(
		'post' => array( 'formData' => 'gswp_ff_token=' . rawurlencode( $sentinel ) ),
		'data' => array(),
	),
	'4. plain $_POST'             => array(
		'post' => array( 'gswp_ff_token' => $sentinel ),
		'data' => array(),
	),
	'5. nothing anywhere'         => array(
		'post' => array(),
		'data' => array(),
	),
);

foreach ( $cases as $label => $case ) {
	$_POST  = $case['post'];
	$result = $call( 'submitted_token', array( $case['data'] ) );

	$verdict = ( $result === $sentinel )
		? 'RECOVERED'
		: ( '' === $result ? 'empty (correct for case 5)' : 'UNEXPECTED: ' . $result );

	printf( "  %-30s %s\n", $label, $verdict );
}

$_POST = $saved;

echo "\n  All of 1-4 should say RECOVERED and 5 should say empty. A resolver that\n";
echo "  only handles one transport is correct until Fluent Forms changes it.\n";

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
// QUESTION 2 — where a rejection message would be displayed.
// ---------------------------------------------------------------------------
echo "\n=== REJECTION TARGET (per form) ===\n\n";
printf( "  %-5s %-34s %-24s %s\n", 'ID', 'TITLE', 'ERROR SHOWN ON FIELD', 'VERDICT' );
echo '  ' . str_repeat( '-', 92 ) . "\n";

$unroutable = 0;

foreach ( $provider->forms() as $form_id => $title ) {
	if ( ! $provider->form_is_eligible( $form_id ) ) {
		continue;
	}

	$field = (string) $call( 'error_field_for', array( $form_id ) );

	if ( '' === $field ) {
		++$unroutable;
		$verdict = 'NO FIELD — will admit + log';
	} else {
		$verdict = 'ok';
	}

	printf(
		"  %-5s %-34s %-24s %s\n",
		$form_id,
		substr( (string) $title, 0, 33 ),
		'' === $field ? '(none)' : $field,
		$verdict
	);
}

if ( $unroutable > 0 ) {
	echo "\n  {$unroutable} form(s) have no field to carry a rejection message. The provider\n";
	echo "  ADMITS those submissions and logs loudly rather than rejecting them,\n";
	echo "  because a rejection the visitor cannot see is indistinguishable from a\n";
	echo "  site outage. Set a target per form with the gswp_ff_error_field filter.\n";
}

// ---------------------------------------------------------------------------
echo "\n=== HOW TO CAPTURE A REAL SUBMISSION ===\n";
echo "  The transport table above proves the resolver handles each envelope. It\n";
echo "  does NOT prove which envelope Fluent Forms actually uses on this site.\n";
echo "\n";
echo "  *** SWITCH THE PROVIDER ON FIRST. ***\n";
echo "\n";
echo "  Settings -> Google Security -> Form Protection -> Fluent Forms.\n";
echo "\n";
echo "  With the provider OFF no token field is rendered into the form at all,\n";
echo "  so the capture below will correctly report 'token in formData: no' and\n";
echo "  settle nothing about our field. It still settles the ENVELOPE, which is\n";
echo "  worth having — but the question of whether OUR key survives Fluent\n";
echo "  Forms' handling needs the field to exist in the first place.\n";
echo "\n";
echo "  Provider state right now: " . ( GSWP_Form_Provider_Registry::is_on( 'fluent-forms' ) ? 'ON — good, capture is meaningful' : 'OFF — turn it on before capturing' ) . "\n";
echo "\n";
echo "  Then add this to a mu-plugin, submit one form in a browser, read the\n";
echo "  log, and REMOVE IT AGAIN:\n\n";
echo "    add_filter( 'fluentform/validation_errors', function ( \$e, \$d, \$f, \$fl ) {\n";
echo "        error_log( 'GSWP POST keys: ' . implode( ',', array_keys( \$_POST ) ) );\n";
echo "        error_log( 'GSWP formData keys: ' . implode( ',', array_keys( (array) \$d ) ) );\n";
echo "        error_log( 'GSWP token in formData: ' . ( isset( \$d['gswp_ff_token'] ) ? 'yes' : 'no' ) );\n";
echo "        return \$e;\n";
echo "    }, 1, 4 );\n\n";
echo "  Expected with the provider ON:\n";
echo "    GSWP POST keys      : ...,data,...          (the serialised envelope)\n";
echo "    GSWP formData keys  : ...,gswp_ff_token,... (our field survived)\n";
echo "    GSWP token in formData: yes\n";
echo "\n";
echo "  A 'no' on the last line WITH the provider on is the one result that\n";
echo "  matters: it means Fluent Forms strips unregistered keys on this version,\n";
echo "  and transport 1 is dead. The submission is still scored — transport 2\n";
echo "  reads the raw envelope — so this is a finding to report, not an outage.\n";
echo "\n";
echo "  Then check the coverage table: the form should show a rejection reason of\n";
echo "  '-' and no coverage gap in the log. Report all three log lines verbatim.\n";

echo "\nReport the whole block above verbatim.\n";
