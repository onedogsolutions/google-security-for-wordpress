<?php
/**
 * GF replacement verification — chunk 4: classification audit (v2.20.1)
 *
 * Read-only. Answers two questions the earlier chunks leave open, both of which
 * decide whether a real submission is handled correctly.
 *
 * 1. WHY is each form classified as payment or not?
 *
 *    The enforcement policy hangs entirely on this. A payment form wrongly
 *    classified as non-payment fails OPEN on a missing token — a real hole, and
 *    the exact case the classifier is meant to be biased against. Chunk 3 only
 *    proves the policy is applied consistently with the classification; it
 *    cannot tell you the classification is right. This prints the evidence so a
 *    human can check it against what the forms actually do.
 *
 * 2. Is Gravity Forms' own reCAPTCHA really gone from the rendered markup?
 *
 *    The version of chunk 2 shipped in 2.20.0 could not answer this: our token
 *    field carries class="g-recaptcha-response", so the search string matched
 *    our own field, and the guard added to avoid that self-match disabled the
 *    check whenever the token was present — i.e. always, in the passing case.
 *    Every "none" it printed was a false negative. This strips our field first.
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
$token    = GSWP_Provider_Gravity_Forms::TOKEN_FIELD;

$out   = array();
$out[] = '=== GF classification audit ===';
$out[] = 'Transaction Defense: ' . ( '1' === get_option( 'gswp_txn_defense', '0' ) ? 'ON' : 'OFF' );
$out[] = 'High-risk blocking:  ' . ( '1' === get_option( 'gswp_txn_block', '0' ) ? 'ON' : 'OFF' );
$out[] = '';

$payment_addons = array(
	'gravityformsstripe',
	'gravityformspaypal',
	'gravityformspaypalcheckout',
	'gravityformssquare',
	'gravityformsauthorizenet',
	'gravityforms2checkout',
	'gravityformsmollie',
	'gravityformsrazorpay',
);

foreach ( $provider->forms() as $form_id => $title ) {
	$form = GFAPI::get_form( (int) $form_id );

	$out[] = '--- #' . $form_id . ' ' . $title . ' ---';

	// Why payment / not payment.
	$reasons     = array();
	$all_feeds   = array();
	$price_types = array();

	if ( method_exists( 'GFAPI', 'get_feeds' ) ) {
		$feeds = GFAPI::get_feeds( null, (int) $form_id );
		if ( is_array( $feeds ) ) {
			foreach ( $feeds as $feed ) {
				$slug   = isset( $feed['addon_slug'] ) ? (string) $feed['addon_slug'] : '?';
				$active = empty( $feed['is_active'] ) ? 'inactive' : 'active';
				$all_feeds[] = $slug . ' (' . $active . ')';

				if ( 'active' === $active && in_array( $slug, $payment_addons, true ) ) {
					$reasons[] = 'active payment feed: ' . $slug;
				}
			}
		}
	}

	if ( is_array( $form ) && ! empty( $form['fields'] ) ) {
		foreach ( $form['fields'] as $field ) {
			$type = is_object( $field ) && isset( $field->type ) ? $field->type : '';
			if ( in_array( $type, array( 'product', 'total', 'shipping', 'option', 'creditcard' ), true ) ) {
				$price_types[] = $type;
			}
		}
		if ( ! empty( $price_types ) ) {
			$reasons[] = 'pricing field(s): ' . implode( ', ', array_unique( $price_types ) );
		}
	}

	$is_payment = $provider->form_has_payment( $form_id );
	$is_account = method_exists( $provider, 'form_creates_account' ) ? $provider->form_creates_account( $form_id ) : false;
	$is_strict  = method_exists( $provider, 'form_is_strict' ) ? $provider->form_is_strict( $form_id ) : $is_payment;

	if ( $is_account ) {
		$reasons[] = 'account-creating feed';
	}

	$out[] = '  classified as : ' . ( $is_strict
		? 'STRICT (missing token -> reject)' . ( $is_payment ? ' [payment]' : '' ) . ( $is_account ? ' [creates account]' : '' )
		: 'ordinary (missing token -> allow + flag)' );
	$out[] = '  feeds         : ' . ( empty( $all_feeds ) ? 'none' : implode( ', ', $all_feeds ) );
	$out[] = '  because       : ' . ( empty( $reasons ) ? 'no payment feed and no pricing field' : implode( ' | ', $reasons ) );
	$out[] = '  GF own captcha: ' . $provider->native_captcha_state( $form_id );
	$out[] = '  eligible      : ' . ( $provider->form_is_eligible( $form_id ) ? 'yes' : 'no' );

	// Does GF's own reCAPTCHA survive in the rendered markup?
	$markup = '';
	try {
		$markup = do_shortcode( '[gravityform id="' . (int) $form_id . '" title="false" description="false" ajax="false"]' );
	} catch ( Throwable $e ) {
		$markup = '';
	}

	if ( '' === $markup ) {
		$out[] = '  rendered      : EMPTY (could not inspect markup)';
	} else {
		$stripped = preg_replace( '/<input[^>]*name="' . preg_quote( $token, '/' ) . '"[^>]*>/i', '', $markup );

		$found = array();
		foreach ( array( 'g-recaptcha', 'grecaptcha', 'data-sitekey', 'gfield_captcha', 'recaptcha/api', 'recaptcha/enterprise' ) as $needle ) {
			if ( false !== stripos( (string) $stripped, $needle ) ) {
				$found[] = $needle;
			}
		}

		$out[] = '  our token     : ' . ( false !== strpos( $markup, 'name="' . $token . '"' ) ? 'present' : 'ABSENT' );
		$out[] = '  GF captcha in markup (our field removed first): '
			. ( empty( $found ) ? 'none' : 'PRESENT -> ' . implode( ', ', $found ) );
	}

	$out[] = '';
}

$out[] = 'HOW TO READ THIS';
$out[] = '';
$out[] = 'Check every form classified as non-payment against what it actually';
$out[] = 'does. A form that takes money but is listed as non-payment will let a';
$out[] = 'submission through when the token is missing. That is the one';
$out[] = 'misclassification that matters; the reverse is only an inconvenience.';
$out[] = '';
$out[] = 'If "GF captcha in markup" says PRESENT anywhere, this plugin did not';
$out[] = 'succeed in standing Gravity Forms\' own reCAPTCHA down. That is not';
$out[] = 'dangerous — both would run and the shared loader deduplicates them —';
$out[] = 'but it means the option name used to disable it is wrong, and the';
$out[] = 'site is paying for two assessments per submission.';
$out[] = '';
$out[] = 'If Transaction Defense is OFF above, payment forms are receiving a';
$out[] = 'plain bot score only: no transaction data is sent, no fraud verdict';
$out[] = 'comes back, and no outcome is reported to Google.';
$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
