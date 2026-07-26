<?php
/**
 * GF replacement verification — chunk 3: enforcement policy (v2.20.0)
 *
 * Drives the real validation filter with synthetic submissions and checks that
 * each one is handled the way the policy says it should be. No network calls
 * and no entries are created — the filter is invoked directly and only its
 * verdict is inspected.
 *
 * Three behaviours are asserted, and the third is the one that matters most:
 *
 *   1. Payment form, no token           -> REJECTED
 *   2. Non-payment form, no token       -> ALLOWED (and the entry flagged)
 *   3. Form we never injected into      -> ALLOWED on every form type
 *
 * (3) is what stands in for the removed staged rollout. If a render path was
 * missed, the visitor must not be the one who pays for it: the submission is
 * let through, logged, and the operator emailed. If this chunk shows a
 * never-injected form being rejected, replacement is unsafe to leave on.
 *
 * MUTATES: temporarily clears the injection log for one form and restores it.
 * Safe to re-run; safe to interrupt (worst case, one form's "token seen"
 * timestamp is cleared and repopulated on the next render).
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'GSWP_Form_Provider_Registry' ) || ! class_exists( 'GFAPI' ) ) {
	echo "STOP: run chunk 11 first.\n";
	return;
}

$provider = GSWP_Form_Provider_Registry::get( 'gravity-forms' );

if ( ! GSWP_Form_Provider_Registry::is_on( 'gravity-forms' ) ) {
	echo "STOP: replacement is off, so the validation filter is not hooked.\n";
	return;
}

$out   = array();
$out[] = '=== GF enforcement policy ===';

$forms = $provider->forms();

// Pick one payment form and one non-payment form to exercise.
$payment_form = 0;
$plain_form   = 0;
foreach ( array_keys( $forms ) as $form_id ) {
	if ( ! $provider->form_is_eligible( $form_id ) ) {
		continue;
	}
	if ( ! $payment_form && $provider->form_has_payment( $form_id ) ) {
		$payment_form = $form_id;
	}
	if ( ! $plain_form && ! $provider->form_has_payment( $form_id ) ) {
		$plain_form = $form_id;
	}
}

$out[] = 'Payment form under test:     ' . ( $payment_form ? '#' . $payment_form : 'none found' );
$out[] = 'Non-payment form under test: ' . ( $plain_form ? '#' . $plain_form : 'none found' );
$out[] = '';

$log_option = GSWP_Provider_Gravity_Forms::INJECTION_OPTION;
$saved_log  = get_option( $log_option, array() );

/**
 * Run the validation filter for a form with the current $_POST state.
 *
 * @param int $form_id Form id.
 * @return bool True when the submission was allowed.
 */
$validate = function ( $form_id ) use ( $provider ) {
	$form   = GFAPI::get_form( (int) $form_id );
	$result = array( 'is_valid' => true, 'form' => $form );
	$result = $provider->validate_submission( $result );

	return ! empty( $result['is_valid'] );
};

$mark = function ( $label, $condition, $detail = '' ) use ( &$out ) {
	$out[] = ( $condition ? 'PASS  ' : 'FAIL  ' ) . $label . ( ! $condition && '' !== $detail ? ' — ' . $detail : '' );
};

$original_post = $_POST;

// --- 1 & 2: a form we HAVE injected into, submitted with no token -----------
$log = is_array( $saved_log ) ? $saved_log : array();

if ( $payment_form ) {
	$log[ (int) $payment_form ] = time();
	update_option( $log_option, $log, false );

	unset( $_POST[ GSWP_Provider_Gravity_Forms::TOKEN_FIELD ] );
	$allowed = $validate( $payment_form );

	$mark(
		'Payment form with no token is REJECTED',
		! $allowed,
		'a payment can be submitted with no verification'
	);
}

if ( $plain_form ) {
	$log[ (int) $plain_form ] = time();
	update_option( $log_option, $log, false );

	unset( $_POST[ GSWP_Provider_Gravity_Forms::TOKEN_FIELD ] );
	$allowed = $validate( $plain_form );

	$mark(
		'Non-payment form with no token is ALLOWED',
		$allowed,
		'a contact form that cannot be submitted is worse than a spam entry'
	);
}

// --- 3: a form we have NEVER injected into ---------------------------------
$never_target = $payment_form ? $payment_form : $plain_form;

if ( $never_target ) {
	$log = is_array( $saved_log ) ? $saved_log : array();
	unset( $log[ (int) $never_target ] );
	update_option( $log_option, $log, false );

	unset( $_POST[ GSWP_Provider_Gravity_Forms::TOKEN_FIELD ] );
	$allowed = $validate( $never_target );

	$mark(
		'Never-injected form is ALLOWED even when it takes payment',
		$allowed,
		'a visitor is being blocked for a coverage gap that is ours, not theirs'
	);

	$out[] = '      (form #' . $never_target . ' used for this case; a COVERAGE GAP line';
	$out[] = '       should now appear in the WooCommerce log, source "gswp")';
}

// --- restore ---------------------------------------------------------------
$_POST = $original_post;
update_option( $log_option, is_array( $saved_log ) ? $saved_log : array(), false );

$out[] = '';
$out[] = 'Injection log restored to its previous state.';
$out[] = '';
$out[] = 'If the third check FAILED, switch Form Protection off before leaving the';
$out[] = 'site — a missed form would be rejecting real visitors.';
$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
