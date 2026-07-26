<?php
/**
 * Manual verification: form provider takeover (v2.19.0)
 *
 * Checks the safety machinery around replacing a form plugin's reCAPTCHA:
 * the kill switch, the takeover state machine, the 'sole' coverage gate, and
 * the asymmetric enforcement policy.
 *
 * Usage:
 *   wp eval-file tests/manual/10-form-provider-takeover.php
 *
 * Read-only: inspects state and pure functions. It does not change options,
 * submit forms, or contact Google.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'GSWP_Form_Provider_Registry' ) ) {
	echo "FAIL: GSWP_Form_Provider_Registry not loaded. Is the plugin active?\n";
	return;
}

$pass  = 0;
$fail  = 0;
$check = function ( $label, $condition, $detail = '' ) use ( &$pass, &$fail ) {
	if ( $condition ) {
		++$pass;
		echo "  PASS  {$label}\n";
	} else {
		++$fail;
		echo "  FAIL  {$label}" . ( '' !== $detail ? " — {$detail}" : '' ) . "\n";
	}
};

echo "\n=== Form provider takeover ===\n";
echo 'Master switch: ' . ( GSWP_Form_Provider_Registry::enabled() ? 'enabled' : 'DISABLED' ) . "\n";
echo 'Gravity Forms stage: ' . GSWP_Form_Provider_Registry::mode( 'gravity-forms' ) . "\n\n";

// ---------------------------------------------------------------------------
echo "1. Safe defaults\n";

$check(
	'Gravity Forms provider is registered',
	null !== GSWP_Form_Provider_Registry::get( 'gravity-forms' )
);
$check(
	'Stored default stage is "off" (upgrading changes nothing)',
	'off' === get_option( GSWP_Form_Provider_Registry::mode_option( 'gravity-forms' ), 'off' )
);
$check(
	'An unknown stage value falls back to "off"',
	'off' === ( function () {
		$opt = GSWP_Form_Provider_Registry::mode_option( 'gravity-forms' );
		$old = get_option( $opt, 'off' );
		update_option( $opt, 'nonsense' );
		$got = GSWP_Form_Provider_Registry::mode( 'gravity-forms' );
		update_option( $opt, $old );
		return $got;
	} )()
);

// ---------------------------------------------------------------------------
echo "\n2. Kill switch\n";

$check(
	'GSWP_DISABLE_FORM_PROVIDERS is honoured',
	! defined( 'GSWP_DISABLE_FORM_PROVIDERS' ) || ! GSWP_Form_Provider_Registry::enabled(),
	'constant is defined but interception is still reported enabled'
);

$opt = GSWP_Form_Provider_Registry::ENABLED_OPTION;
$old = get_option( $opt, '1' );
update_option( $opt, '0' );
$killed_mode = GSWP_Form_Provider_Registry::mode( 'gravity-forms' );
$killed_flag = GSWP_Form_Provider_Registry::enabled();
update_option( $opt, $old );

$check( 'Master switch off reports disabled', ! $killed_flag );
$check(
	'Master switch off forces every stage to "off"',
	'off' === $killed_mode,
	'runtime and UI would disagree about whether interception is live'
);

// ---------------------------------------------------------------------------
echo "\n3. The 'sole' coverage gate\n";

$audit = GSWP_Form_Provider_Registry::audit( 'gravity-forms' );

if ( ! $audit['available'] ) {
	echo "  SKIP  Gravity Forms is not active on this site\n";
} else {
	printf(
		"  INFO  %d forms, %d uncovered, %d ineligible\n",
		count( $audit['forms'] ),
		count( $audit['uncovered'] ),
		count( $audit['ineligible'] )
	);

	$sole = GSWP_Form_Provider_Registry::can_set_mode( 'gravity-forms', 'sole' );

	if ( empty( $audit['uncovered'] ) ) {
		$check( 'Sole is permitted when every eligible form is covered', true === $sole );
	} else {
		$check(
			'Sole is REFUSED while eligible forms are uncovered',
			is_wp_error( $sole ),
			'the form plugin’s reCAPTCHA could be retired while forms are unprotected'
		);
	}

	$check(
		'Shadow is always permitted',
		true === GSWP_Form_Provider_Registry::can_set_mode( 'gravity-forms', 'shadow' )
	);
	$check(
		'An unknown stage is refused',
		is_wp_error( GSWP_Form_Provider_Registry::can_set_mode( 'gravity-forms', 'wide-open' ) )
	);

	echo "\n4. Per-form policy\n";
	foreach ( $audit['forms'] as $form ) {
		printf(
			"  #%-4s %-34s covered=%-3s payment=%-3s missing-token=%-12s own=%s\n",
			$form['id'],
			mb_substr( $form['title'], 0, 34 ),
			$form['covered'] ? 'yes' : 'no',
			$form['payment'] ? 'yes' : 'no',
			'reject' === $form['enforcement'] ? 'reject' : 'allow+flag',
			$form['native']
		);
	}

	$mismatch = array();
	foreach ( $audit['forms'] as $form ) {
		// Payment forms must fail closed; everything else fails open.
		$expected = $form['payment'] ? 'reject' : 'allow';
		if ( $form['enforcement'] !== $expected ) {
			$mismatch[] = $form['id'];
		}
	}
	$check(
		'Enforcement policy matches payment status on every form',
		empty( $mismatch ),
		'forms: ' . implode( ', ', $mismatch )
	);

	$v2 = array();
	foreach ( $audit['forms'] as $form ) {
		if ( 'v2' === $form['native'] && $form['eligible'] ) {
			$v2[] = $form['id'];
		}
	}
	$check(
		'v2 checkbox forms are excluded from takeover',
		empty( $v2 ),
		'forms: ' . implode( ', ', $v2 )
	);
}

// ---------------------------------------------------------------------------
echo "\n5. Annotation is reachable without WooCommerce\n";

$check(
	'Transaction Defense annotation is source-agnostic',
	method_exists( 'GSWP_Transaction_Defense', 'annotate_assessment' ),
	'a Gravity Forms payment could be assessed but never annotated'
);

echo "\n=== {$pass} passed, {$fail} failed ===\n";

echo <<<'NOTES'

Browser scenarios to run manually on staging
--------------------------------------------
BEFORE ADVANCING ANY FORM TO 'sole', confirm the Gravity Forms bindings against
the installed source. The hook names, feed meta keys and native-captcha option
names in class-gswp-provider-gravity-forms.php are marked UNVERIFIED.

 A. Shadow mode, token generation deliberately broken (block
    www.google.com/recaptcha in the browser or via CSP)
    -> GF's own reCAPTCHA still protects the form
    -> submissions still succeed
    -> our log records "submitted with no reCAPTCHA token"
    -> NO customer impact. If this fails, do not proceed past shadow.

 B. Sole mode, token generation deliberately broken
    -> non-payment forms STILL SUBMIT (fail-open), entry flagged gswp_unverified
    -> payment forms reject cleanly with a readable message
    -> this is the test that justifies the enforcement split; if it fails,
       the split is wrong and sole mode must not ship

 C. Kill switch thrown mid-traffic (toggle in settings, or define
    GSWP_DISABLE_FORM_PROVIDERS in wp-config.php)
    -> all interception stops at once, no fatals
    -> forms submit normally
    -> GF's own reCAPTCHA can be re-enabled and works

 D. Coverage audit vs reality
    -> for EVERY form the audit calls covered, view-source and confirm the
       gswp_gf_token input is actually present
    -> check multi-page, AJAX-enabled, and conditional-logic forms specifically:
       gform_submit_button is assumed to fire on all render paths and that
       assumption is UNVERIFIED

 E. v2 checkbox form
    -> reported ineligible, excluded from takeover, GF's reCAPTCHA untouched

 F. Payment form, transaction risk above threshold, blocking enabled
    -> rejected BEFORE the card is charged
    -> verify in the Stripe dashboard that NO authorisation was created; a
       server-side block does not necessarily void a client-side authorisation

 G. Rollback from sole
    -> re-enable GF's reCAPTCHA, set the stage back to shadow
    -> protection restored, and 2.18.x dedup still yields ONE loader tag

NOTES;

echo "\n";
