<?php
/**
 * Fluent Forms replacement verification — chunk 26: enforcement guards (v2.23.0)
 *
 * The regression guards. Every assertion here runs offline: no network call, no
 * test submission, no entry created. Each one exists because the equivalent
 * defect has already shipped once on the Gravity Forms provider.
 *
 *   A. ACTION PAIRING. The provider used to decide the reCAPTCHA action twice —
 *      once when rendering the token field, once when validating — and the two
 *      expressions drifted. A non-payment form with a User Registration feed
 *      rendered "submit" but was validated as "register", and Enterprise
 *      assessments reject on expectedAction mismatch BEFORE scoring. Every
 *      submission of every account form failed, for every visitor, with a
 *      message accusing them of being spam. This asserts the rendered attribute
 *      and the resolved action agree.
 *
 *   B. COVERAGE ASSERTION. A form we have never injected into must be ADMITTED
 *      when its token is missing, including a payment form. A missing token
 *      there is our coverage bug, not an attack, and a visitor must never be
 *      blocked for it.
 *
 *   C. "NOT PUBLIC" DOES NOT REMOVE PROTECTION. The declaration suppresses the
 *      missing-token alarm and nothing else. A declared form stays eligible and
 *      keeps its token field. The first cut of this on Gravity Forms made an
 *      internal form ineligible, which silently stripped bot scoring from a
 *      password-change form reachable in a browser.
 *
 *   D. PROVIDER ISOLATION. Enabling Fluent Forms must not alter any Gravity
 *      Forms option, threshold or coverage row.
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
$call    = function ( $method, $args ) use ( $provider, $reflect ) {
	$m = $reflect->getMethod( $method );
	$m->setAccessible( true );

	return $m->invokeArgs( $provider, $args );
};

$pass = 0;
$fail = 0;

$assert = function ( $label, $ok, $detail = '' ) use ( &$pass, &$fail ) {
	if ( $ok ) {
		++$pass;
		echo '  PASS  ' . $label . ( '' !== $detail ? '  (' . $detail . ')' : '' ) . "\n";
	} else {
		++$fail;
		echo '  FAIL  ' . $label . ( '' !== $detail ? '  (' . $detail . ')' : '' ) . "\n";
	}
};

// ---------------------------------------------------------------------------
// A. Action pairing.
// ---------------------------------------------------------------------------
echo "=== A. ACTION PAIRING (render vs validation) ===\n\n";

foreach ( $provider->forms() as $form_id => $title ) {
	if ( ! $provider->form_is_eligible( $form_id ) ) {
		continue;
	}

	$markup   = (string) $call( 'token_field', array( $form_id ) );
	$resolved = (string) $call( 'action_for', array( $form_id ) );
	$accepted = (array) $call( 'accepted_actions', array( $form_id ) );

	$rendered = '';
	if ( preg_match( '/data-recaptcha-action="([^"]*)"/', $markup, $m ) ) {
		$rendered = $m[1];
	}

	$assert(
		sprintf( 'form #%-3s %-28s rendered "%s"', $form_id, substr( (string) $title, 0, 27 ), $rendered ),
		'' !== $rendered && $rendered === $resolved && in_array( $rendered, $accepted, true ),
		'expects "' . implode( '" or "', $accepted ) . '"'
	);
}

// ---------------------------------------------------------------------------
// B. Coverage assertion — a never-injected form is admitted, even on payment.
// ---------------------------------------------------------------------------
echo "\n=== B. COVERAGE ASSERTION (never-injected form must be ADMITTED) ===\n\n";

$log        = get_option( GSWP_Provider_Fluent_Forms::INJECTION_OPTION, array() );
$log        = is_array( $log ) ? $log : array();
$never      = array();
$strict_yet = array();

foreach ( $provider->forms() as $form_id => $title ) {
	if ( ! $provider->form_is_eligible( $form_id ) ) {
		continue;
	}
	if ( 0 === $provider->last_injection( $form_id ) ) {
		$never[ $form_id ] = $title;
		if ( $provider->form_is_strict( $form_id ) ) {
			$strict_yet[ $form_id ] = $title;
		}
	}
}

if ( empty( $never ) ) {
	echo "  Every eligible form has been injected into at least once, so this\n";
	echo "  branch cannot be exercised here. Run chunk 21 on a fresh install to\n";
	echo "  see it, or clear the option below and re-run.\n";
	echo '  (option: ' . GSWP_Provider_Fluent_Forms::INJECTION_OPTION . ")\n";
} else {
	echo '  ' . count( $never ) . " form(s) have never been injected into:\n";
	foreach ( $never as $form_id => $title ) {
		echo '    #' . $form_id . '  ' . $title . ( isset( $strict_yet[ $form_id ] ) ? '   [STRICT — must still be admitted]' : '' ) . "\n";
	}
	echo "\n";

	// Exercise the real branch rather than inspecting the source. The
	// coverage-gap path fires gswp_form_coverage_gap, which the alert layer
	// turns into an operator email — so its listeners are detached for the
	// duration and restored afterwards. A test that emails the operator every
	// time it runs is the same "alert that cries wolf" problem this branch
	// exists to avoid.
	$saved_listeners = isset( $GLOBALS['wp_filter']['gswp_form_coverage_gap'] )
		? $GLOBALS['wp_filter']['gswp_form_coverage_gap']
		: null;
	unset( $GLOBALS['wp_filter']['gswp_form_coverage_gap'] );

	$saved_post = $_POST; // phpcs:ignore WordPress.Security.NonceVerification
	$_POST      = array();

	foreach ( $never as $form_id => $title ) {
		$result = $provider->validate_submission(
			array(),
			array(),
			(object) array( 'id' => (int) $form_id ),
			array()
		);

		$assert(
			sprintf( 'never-injected form #%-3s admitted with no token', $form_id ),
			is_array( $result ) && empty( $result ),
			$provider->form_is_strict( $form_id ) ? 'STRICT form — this is the one that matters' : 'non-strict'
		);
	}

	$_POST = $saved_post;

	if ( null !== $saved_listeners ) {
		$GLOBALS['wp_filter']['gswp_form_coverage_gap'] = $saved_listeners;
	}

	echo "\n  Each of these also wrote a COVERAGE GAP line to the log, which is\n";
	echo "  correct — that is the alarm doing its job. No operator email was\n";
	echo "  sent: the alert listeners were detached for the duration.\n";
}

// ---------------------------------------------------------------------------
// C. "Not public" suppresses the alarm, never the protection.
// ---------------------------------------------------------------------------
echo "\n=== C. \"NOT PUBLIC\" DOES NOT REMOVE PROTECTION ===\n\n";

$forms = array_keys( $provider->forms() );

if ( empty( $forms ) ) {
	echo "  No forms to test.\n";
} else {
	$probe = 0;
	foreach ( $forms as $candidate ) {
		if ( $provider->form_is_eligible( $candidate ) ) {
			$probe = $candidate;
			break;
		}
	}

	if ( ! $probe ) {
		echo "  No eligible form to test with.\n";
	} else {
		// Declare it internal via the filter rather than the option, so nothing
		// is written and the operator's real list is untouched.
		$mark = function ( $internal, $form_id ) use ( $probe ) {
			return (int) $form_id === (int) $probe ? true : $internal;
		};
		add_filter( 'gswp_ff_form_is_internal', $mark, 10, 2 );

		$assert( 'declared form reports internal', $provider->form_is_internal( $probe ), 'form #' . $probe );
		$assert( 'declared form is STILL eligible', $provider->form_is_eligible( $probe ), 'protection intact' );
		$assert(
			'declared form STILL renders a token field',
			false !== strpos( (string) $call( 'token_field', array( $probe ) ), 'g-recaptcha-response' ),
			'a submission carrying a token is still scored'
		);

		remove_filter( 'gswp_ff_form_is_internal', $mark, 10 );

		// The filter is gone, so the answer must come from the stored list
		// alone. Anything else means the test left residue behind.
		$stored = array_map( 'intval', (array) get_option( GSWP_Provider_Fluent_Forms::INTERNAL_OPTION, array() ) );
		$assert(
			'filter removal leaves no residue',
			$provider->form_is_internal( $probe ) === in_array( (int) $probe, $stored, true ),
			'state now comes from the stored list alone'
		);
	}
}

// ---------------------------------------------------------------------------
// D. Provider isolation.
// ---------------------------------------------------------------------------
echo "\n=== D. PROVIDER ISOLATION ===\n\n";

$gf_options = array(
	'gswp_provider_gravity_forms_enabled',
	'gswp_gf_internal_forms',
	'gswp_gf_injection_log',
	'gswp_gf_last_rejection',
	'gswp_threshold_gf_submit',
	'gswp_threshold_gf_register',
	'gswp_threshold_gf_account_update',
	'gswp_threshold_gf_password',
);

$before = array();
foreach ( $gf_options as $option ) {
	$before[ $option ] = get_option( $option, null );
}

// Exercise every read path on the Fluent Forms provider.
foreach ( array_keys( $provider->forms() ) as $form_id ) {
	$provider->form_is_eligible( $form_id );
	$provider->form_is_strict( $form_id );
	$provider->native_captcha_state( $form_id );
	if ( method_exists( $provider, 'form_policy' ) ) {
		$provider->form_policy( $form_id );
	}
}
GSWP_Form_Provider_Registry::audit( 'fluent-forms' );

$drifted = array();
foreach ( $gf_options as $option ) {
	if ( get_option( $option, null ) !== $before[ $option ] ) {
		$drifted[] = $option;
	}
}

$assert(
	'no Gravity Forms option changed',
	empty( $drifted ),
	empty( $drifted ) ? count( $gf_options ) . ' options checked' : implode( ', ', $drifted )
);

// The two providers must not share option keys at all.
$ff_constants = array( 'INJECTION_OPTION', 'REJECTION_OPTION', 'INTERNAL_OPTION', 'TOKEN_FIELD' );
$collisions   = array();
foreach ( $ff_constants as $name ) {
	$ff = constant( 'GSWP_Provider_Fluent_Forms::' . $name );
	$gf = constant( 'GSWP_Provider_Gravity_Forms::' . $name );
	if ( $ff === $gf ) {
		$collisions[] = $name . ' = ' . $ff;
	}
}

$assert(
	'no option or field name shared with Gravity Forms',
	empty( $collisions ),
	empty( $collisions ) ? implode( ', ', $ff_constants ) : implode( '; ', $collisions )
);

// ---------------------------------------------------------------------------
echo "\n=== RESULT ===\n\n";
echo "  passed: {$pass}   failed: {$fail}\n\n";

if ( $fail > 0 ) {
	echo "  DO NOT ENABLE the Fluent Forms provider on a live site until every\n";
	echo "  check above passes. Section A failing is the one that rejects every\n";
	echo "  visitor on an account form; section B failing is the one that blocks\n";
	echo "  people for our own coverage bug.\n";
} else {
	echo "  All guards passed. This does not replace chunks 21-25 — it asserts\n";
	echo "  that the logic is self-consistent, not that the bindings are right.\n";
}

echo "\nReport the whole block above verbatim.\n";
