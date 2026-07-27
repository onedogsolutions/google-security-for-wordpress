<?php
/**
 * GF replacement verification — chunk 19: action pairing (v2.22.0)
 *
 * The regression guard for the defect that rejected every Gravity Forms account
 * form.
 *
 * The provider used to decide the reCAPTCHA action twice: once when rendering
 * the hidden token field (which tells the browser what to mint), and once when
 * validating (which tells Google what to expect). The two expressions drifted —
 * a non-payment form with a User Registration feed rendered "submit" but was
 * validated as "register" — and reCAPTCHA Enterprise rejects on expectedAction
 * mismatch. Every submission of every account form failed, for every visitor,
 * with a message accusing them of being spam.
 *
 * This chunk asserts the two sides agree, by rendering the real field and
 * comparing the attribute it carries against the action the provider resolves
 * for that form. It needs no network call, no test submission and no entry: it
 * would have caught the original defect on any install, offline.
 *
 * It also prints each form's User Registration feed type verbatim. That binding
 * (`meta['feedType']` being 'create' or 'update') is UNVERIFIED against the
 * installed Gravity Forms source, and the classification of profile-edit forms
 * as non-strict rests on it. Report the FEED INVENTORY block below.
 *
 * MUTATES: rendering a field records an injection timestamp, so the injection
 * log is saved and restored. Safe to re-run; safe to interrupt (worst case, one
 * form's "token seen" timestamp is refreshed).
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

if ( null === $provider ) {
	echo "STOP: the Gravity Forms provider is not registered.\n";
	return;
}

if ( ! GSWP_Recaptcha_Loader::will_load() ) {
	echo "STOP: no reCAPTCHA site key is configured, so no token field is rendered.\n";
	return;
}

// Run context. Printed by every chunk so a result can always be tied to the
// plugin version and site that produced it.
$gswp_ctx = array(
	'=== RUN CONTEXT ===',
	'  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ),
	'  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ),
	'  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ),
	'  php            : ' . PHP_VERSION,
	'  key type       : ' . get_option( 'gswp_key_type', 'classic' ),
	'',
);
echo implode( "\n", $gswp_ctx ) . "\n";

$out   = array();
$out[] = '=== GF action pairing ===';
$out[] = '';

$log_option = GSWP_Provider_Gravity_Forms::INJECTION_OPTION;
$saved_log  = get_option( $log_option, array() );

$forms    = $provider->forms();
$failures = 0;
$checked  = 0;

foreach ( $forms as $form_id => $title ) {
	if ( ! $provider->form_is_eligible( $form_id ) ) {
		$out[] = sprintf( 'SKIP  #%d %s — ineligible (keeps GF\'s own reCAPTCHA)', $form_id, $title );
		continue;
	}

	$form = GFAPI::get_form( (int) $form_id );
	if ( ! is_array( $form ) ) {
		$out[] = sprintf( 'SKIP  #%d %s — form could not be read', $form_id, $title );
		continue;
	}

	// Render the real field through the real hook.
	$markup   = $provider->inject_token_field( '<!--button-->', $form );
	$rendered = '';
	if ( preg_match( '/data-recaptcha-action="([^"]*)"/', $markup, $m ) ) {
		$rendered = $m[1];
	}

	$policy   = method_exists( $provider, 'form_policy' ) ? $provider->form_policy( $form_id ) : array();
	$expected = isset( $policy['action'] ) ? $policy['action'] : '(unavailable)';
	$context  = isset( $policy['context'] ) ? $policy['context'] : '(unavailable)';

	++$checked;

	if ( '' === $rendered ) {
		++$failures;
		$out[] = sprintf( 'FAIL  #%d %s — no token field was rendered at all', $form_id, $title );
		continue;
	}

	$agree = ( $rendered === $expected );
	if ( ! $agree ) {
		++$failures;
	}

	$out[] = sprintf(
		'%s  #%d %s',
		$agree ? 'PASS' : 'FAIL',
		$form_id,
		$title
	);
	$out[] = sprintf( '        rendered action : %s', $rendered );
	$out[] = sprintf( '        expected action : %s%s', $expected, $agree ? '' : '   <-- MISMATCH: this form rejects every submission' );
	$out[] = sprintf(
		'        threshold       : gswp_threshold_%s = %s',
		$context,
		get_option( 'gswp_threshold_' . $context, '0.5' )
	);
	$out[] = sprintf(
		'        enforcement     : %s',
		$provider->form_is_strict( $form_id ) ? 'reject on missing token' : 'allow on missing token'
	);
}

// Restore: inject_token_field() records an injection timestamp, and a form that
// has never really been rendered must keep reporting a coverage gap.
update_option( $log_option, is_array( $saved_log ) ? $saved_log : array(), false );

$out[] = '';
$out[] = sprintf( 'Checked %d eligible form(s): %d mismatch(es).', $checked, $failures );
$out[] = 'Injection log restored to its previous state.';

// --- Feed inventory: confirms the UNVERIFIED feedType binding ---------------
// --- Field inventory: confirms the password-field binding -------------------
$out[] = '';
$out[] = '=== FIELD INVENTORY (report this block verbatim) ===';
$out[] = 'Password-changing forms are classified from a field of type "password".';
$out[] = 'If a form below sets or changes a password but shows password=no, that';
$out[] = 'binding is wrong and the form is being scored under the wrong threshold.';
$out[] = '';

foreach ( $forms as $form_id => $title ) {
	$form = GFAPI::get_form( (int) $form_id );
	if ( ! is_array( $form ) || empty( $form['fields'] ) || ! is_array( $form['fields'] ) ) {
		continue;
	}

	$types = array();
	foreach ( $form['fields'] as $field ) {
		if ( is_object( $field ) && isset( $field->type ) ) {
			$types[] = (string) $field->type;
		}
	}

	$out[] = sprintf(
		'  #%d %s  password=%s',
		$form_id,
		$title,
		method_exists( $provider, 'form_changes_password' ) && $provider->form_changes_password( $form_id ) ? 'yes' : 'no'
	);
	$out[] = '      field types: ' . ( $types ? implode( ', ', array_unique( $types ) ) : '(none)' );
}

$out[] = '';
$out[] = '=== FEED INVENTORY (report this block verbatim) ===';
$out[] = 'Confirms whether User Registration feeds really declare meta[feedType],';
$out[] = 'which is what separates "creates an account" from "updates one".';
$out[] = '';

if ( ! method_exists( 'GFAPI', 'get_feeds' ) ) {
	$out[] = '  GFAPI::get_feeds() is unavailable — classification cannot be confirmed.';
} else {
	foreach ( $forms as $form_id => $title ) {
		$feeds = GFAPI::get_feeds( null, (int) $form_id );
		if ( ! is_array( $feeds ) || empty( $feeds ) ) {
			continue;
		}

		$lines = array();
		foreach ( $feeds as $feed ) {
			$slug = isset( $feed['addon_slug'] ) ? (string) $feed['addon_slug'] : '(none)';
			if ( false === stripos( $slug, 'userregistration' ) ) {
				continue;
			}

			$meta = isset( $feed['meta'] ) && is_array( $feed['meta'] ) ? $feed['meta'] : array();

			$lines[] = sprintf(
				'    %s  active=%s  feedType=%s',
				$slug,
				empty( $feed['is_active'] ) ? 'no' : 'yes',
				array_key_exists( 'feedType', $meta ) ? var_export( $meta['feedType'], true ) : 'KEY ABSENT'
			);

			// If the key is absent the binding is wrong and every profile-edit
			// form is still being treated as a signup. Show what keys DO exist
			// so the correct one can be identified without another round trip.
			if ( ! array_key_exists( 'feedType', $meta ) ) {
				$lines[] = '      meta keys present: ' . implode( ', ', array_keys( $meta ) );
			}
		}

		if ( ! empty( $lines ) ) {
			$out[] = sprintf( '  #%d %s', $form_id, $title );
			$out   = array_merge( $out, $lines );
		}
	}
}

$out[] = '';
$out[] = 'A MISMATCH above means that form is rejecting every real submission with';
$out[] = '"we could not verify this submission". Switch Form Protection off until it';
$out[] = 'is fixed — Gravity Forms\' own reCAPTCHA resumes on the next request.';
$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
