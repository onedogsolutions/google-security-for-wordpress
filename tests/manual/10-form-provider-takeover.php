<?php
/**
 * Manual verification: form provider replacement (v2.20.0)
 *
 * Checks the machinery around replacing a form plugin's reCAPTCHA: the kill
 * switch, the on/off state, reversibility of the native disable, the coverage
 * assertion, and the asymmetric enforcement policy.
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
echo 'Gravity Forms replacement: ' . ( GSWP_Form_Provider_Registry::is_on( 'gravity-forms' ) ? 'ON' : 'off' ) . "\n\n";

// ---------------------------------------------------------------------------
echo "1. Safe defaults\n";

$check(
	'Gravity Forms provider is registered',
	null !== GSWP_Form_Provider_Registry::get( 'gravity-forms' )
);
$check(
	'Provider exposes an on/off state, not a stage',
	method_exists( 'GSWP_Form_Provider_Registry', 'is_on' )
		&& ! method_exists( 'GSWP_Form_Provider_Registry', 'mode' )
);
$check(
	'Provider can disable the host plugin\'s own reCAPTCHA',
	method_exists( 'GSWP_Provider_Gravity_Forms', 'disable_native' )
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
$killed_mode = GSWP_Form_Provider_Registry::is_on( 'gravity-forms' ) ? 'on' : 'off';
$killed_flag = GSWP_Form_Provider_Registry::enabled();
update_option( $opt, $old );

$check( 'Master switch off reports disabled', ! $killed_flag );
$check(
	'Master switch off forces every provider off',
	'off' === $killed_mode,
	'runtime and UI would disagree about whether interception is live'
);

// ---------------------------------------------------------------------------
echo "\n3. Native disable is reversible\n";

$provider = GSWP_Form_Provider_Registry::get( 'gravity-forms' );

$check(
	'Blanking GF settings is a read-time filter, not a write',
	method_exists( $provider, 'blank_native_settings' )
);

if ( method_exists( $provider, 'blank_native_settings' ) ) {
	$sample = array( 'site_key' => 'REALKEY', 'secret_key' => 'REALSECRET', 'other' => 'keep' );
	$masked = $provider->blank_native_settings( $sample );

	$check( 'Site key is blanked', '' === $masked['site_key'] );
	$check( 'Secret key is blanked', '' === $masked['secret_key'] );
	$check( 'Unrelated settings are preserved', 'keep' === $masked['other'] );
	$check( 'Non-array values pass through untouched', false === $provider->blank_native_settings( false ) );
}

// ---------------------------------------------------------------------------
echo "\n4. Coverage report and enforcement policy\n";

$audit = GSWP_Form_Provider_Registry::audit( 'gravity-forms' );

if ( ! $audit['available'] ) {
	echo "  SKIP  Gravity Forms is not active on this site\n";
} else {
	printf(
		"  INFO  %d forms, %d ineligible, replacement %s\n",
		count( $audit['forms'] ),
		count( $audit['ineligible'] ),
		$audit['on'] ? 'ON' : 'off'
	);

	foreach ( $audit['forms'] as $form ) {
		printf(
			"  #%-4s %-32s eligible=%-3s payment=%-3s missing-token=%-11s token-seen=%-9s own=%s\n",
			$form['id'],
			mb_substr( $form['title'], 0, 32 ),
			$form['eligible'] ? 'yes' : 'no',
			$form['payment'] ? 'yes' : 'no',
			'reject' === $form['enforcement'] ? 'reject' : 'allow+flag',
			$form['injected'] ? gmdate( 'Y-m-d', $form['injected'] ) : 'never',
			$form['native']
		);
	}

	$mismatch = array();
	foreach ( $audit['forms'] as $form ) {
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
		'v2 checkbox forms are excluded from replacement',
		empty( $v2 ),
		'forms: ' . implode( ', ', $v2 )
	);

	// The coverage assertion is the thing standing in for the removed shadow
	// stage: a covered form that has never been observed receiving a token is
	// the signal that a render path was missed.
	$never = array();
	foreach ( $audit['forms'] as $form ) {
		if ( $form['covered'] && empty( $form['injected'] ) ) {
			$never[] = $form['id'];
		}
	}
	if ( $audit['on'] ) {
		$check(
			'Every covered form has been observed receiving a token field',
			empty( $never ),
			'never observed on forms: ' . implode( ', ', $never ) . ' — load them on the front end, then re-run'
		);
	} else {
		echo "  SKIP  replacement is off, so no injections are expected yet\n";
	}
}

// ---------------------------------------------------------------------------
echo "\n5. Annotation and alerting\n";

$check(
	'Transaction Defense annotation is source-agnostic',
	method_exists( 'GSWP_Transaction_Defense', 'annotate_assessment' ),
	'a Gravity Forms payment could be assessed but never annotated'
);
$check(
	'Coverage gaps reach the alert pipeline',
	method_exists( 'GSWP_Alerts', 'on_form_coverage_gap' ),
	'a form submitted unscored would only ever reach the log'
);

echo "\n=== {$pass} passed, {$fail} failed ===\n";

echo <<<'NOTES'

Browser scenarios to run manually on staging
--------------------------------------------
The Gravity Forms bindings in class-gswp-provider-gravity-forms.php are still
marked UNVERIFIED against the installed source. The fallback injection and the
coverage assertion are designed so a wrong binding shows up as a warning rather
than an unprotected form — scenarios 2-4 and 8 are what prove that.

 1. Ordinary GF form, replacement on
    -> view-source shows a hidden gswp_gf_token input
    -> GF's own reCAPTCHA script is NOT on the page
    -> submission succeeds and is scored

 2. Multi-page form            -> token present and fresh at the final submit
 3. AJAX-enabled form          -> same
 4. Theme overriding the submit button
    -> token still present, placed by the markup fallback rather than the
       submit-button hook

 5. GF Stripe payment, good score
    -> completes; assessment carries transactionData; entry meta records the
       assessment name; annotated LEGITIMATE on payment completion

 6. GF Stripe payment, transaction risk above threshold, blocking on
    -> rejected BEFORE the card is charged
    -> CONFIRM IN THE STRIPE DASHBOARD that no authorisation was created. In
       some GF Stripe modes the card is authorised client-side before
       submission, in which case a server-side rejection stops the entry but
       not the hold. This is the one outstanding discovery item that can cost a
       customer real money.

 7. Token generation deliberately broken (block www.google.com/recaptcha)
    -> non-payment forms still submit, entries flagged gswp_unverified
    -> payment forms reject cleanly with a readable message

 8. A form we never injected into (simulate: return early from
    inject_token_field and inject_into_markup for one form id)
    -> submission is ACCEPTED, not blocked
    -> log records "COVERAGE GAP" naming the form
    -> operator receives an email
    -> this is the test that decides whether a missed render path is loud or
       silent; if it fails, nothing else in this release is trustworthy

 9. v2 checkbox form
    -> untouched: GF's captcha still renders and still validates
    -> reported "not eligible" in the Form Protection panel

10. Turn replacement off
    -> GF's own reCAPTCHA returns on the very next page load
    -> nothing in GF's settings needs re-entering

11. Kill switch (toggle, or define GSWP_DISABLE_FORM_PROVIDERS in wp-config.php)
    -> same as 10, immediately, without touching the plugin's settings

12. WooCommerce checkout             -> unaffected (regression check)

NOTES;

echo "\n";
