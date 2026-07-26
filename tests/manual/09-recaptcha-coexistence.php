<?php
/**
 * Manual verification: reCAPTCHA loader coexistence (v2.18.0)
 *
 * Verifies that this plugin shares a single reCAPTCHA loader with any other
 * plugin using the same site key, never suppresses a matching-key loader, and
 * reports divergent site keys loudly.
 *
 * This covers the regression that broke Gravity Forms' Stripe payment element
 * in 2.16.0 and the "verification token is missing" outage its emergency fix
 * introduced.
 *
 * Usage:
 *   wp eval-file tests/manual/09-recaptcha-coexistence.php
 *
 * The script is read-only: it simulates registered scripts in memory and
 * inspects the loader's decisions. It does not change any option or write to
 * the database. Front-end scenarios that need a real browser are listed at the
 * end for manual execution.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'GSWP_Recaptcha_Loader' ) ) {
	echo "FAIL: GSWP_Recaptcha_Loader not loaded. Is the plugin active?\n";
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

$our_key = GSWP_Recaptcha_Loader::site_key();

echo "\n=== reCAPTCHA loader coexistence ===\n";
echo 'Configured site key: ' . ( '' === $our_key ? '(none)' : GSWP_Recaptcha_Loader::mask_key( $our_key ) ) . "\n";
echo 'Conflict mode: ' . get_option( 'gswp_conflict_mode', 'off' ) . "\n\n";

// ---------------------------------------------------------------------------
echo "1. Site key parsing\n";

$check(
	'Enterprise loader src yields its render key',
	'ABC123' === GSWP_Recaptcha_Loader::key_from_src( 'https://www.google.com/recaptcha/enterprise.js?render=ABC123' )
);
$check(
	'Classic loader src yields its render key',
	'XYZ789' === GSWP_Recaptcha_Loader::key_from_src( 'https://www.google.com/recaptcha/api.js?render=XYZ789' )
);
$check(
	'render=explicit is treated as no key',
	'' === GSWP_Recaptcha_Loader::key_from_src( 'https://www.google.com/recaptcha/api.js?render=explicit' )
);
$check(
	'Loader with no render parameter yields no key',
	'' === GSWP_Recaptcha_Loader::key_from_src( 'https://www.google.com/recaptcha/api.js' )
);
$check(
	'Non-reCAPTCHA src is not recognised',
	! GSWP_Recaptcha_Loader::is_recaptcha_src( 'https://example.com/app.js' )
);
$check(
	'recaptcha.net mirror is recognised',
	GSWP_Recaptcha_Loader::is_recaptcha_src( 'https://www.recaptcha.net/recaptcha/api.js?render=K' )
);

// ---------------------------------------------------------------------------
echo "\n2. Deduplication (same key => one tag)\n";

$tag_for = function ( $handle, $key ) {
	$src = 'https://www.google.com/recaptcha/enterprise.js?render=' . $key;

	return GSWP_Recaptcha_Loader::filter_tag(
		'<script src="' . $src . '"></script>',
		$handle,
		$src
	);
};

// Reset per-request state between simulated page renders.
$reset = function () {
	$ref  = new ReflectionClass( 'GSWP_Recaptcha_Loader' );
	$prop = $ref->getProperty( 'emitted_keys' );
	$prop->setAccessible( true );
	$prop->setValue( null, array() );
};

$reset();
$first  = $tag_for( 'gform_recaptcha', 'SHAREDKEY123456' );
$second = $tag_for( 'google-recaptcha-v3', 'SHAREDKEY123456' );

$check( 'First loader for a key is emitted', '' !== $first );
$check( 'Second loader for the same key is dropped', '' === $second, 'duplicate tag survived' );

$reset();
$a = $tag_for( 'google-recaptcha-v3', 'KEY_AAAAAAAAAAA' );
$b = $tag_for( 'gform_recaptcha', 'KEY_BBBBBBBBBBB' );

$check( 'Our loader is emitted', '' !== $a );
$check( 'A different key is NOT deduplicated away', '' !== $b, 'divergent loader was silently dropped' );

// ---------------------------------------------------------------------------
echo "\n3. Conflict Guard never suppresses a matching key\n";

if ( '' === $our_key ) {
	echo "  SKIP  no site key configured; configure one to exercise this section\n";
} else {
	$guard = new GSWP_Conflict_Guard();
	$src   = 'https://www.google.com/recaptcha/enterprise.js?render=' . $our_key;
	$tag   = '<script src="' . $src . '"></script>';

	$check(
		'Matching-key third-party loader survives the Conflict Guard',
		$tag === $guard->filter_tag( $tag, 'gform_recaptcha', $src ),
		'this is the 2.16.0 Stripe regression'
	);
}

// ---------------------------------------------------------------------------
echo "\n4. Print / enforce agreement (no token-missing outage)\n";

$check(
	'will_load() depends only on stored options',
	GSWP_Recaptcha_Loader::will_load() === ( '' !== get_option( 'gswp_site_key', '' ) )
);
$check(
	'Deferral machinery is gone',
	! method_exists( 'GSWP_Gravity_Forms', 'should_defer' )
		&& ! method_exists( 'GSWP_Gravity_Forms', 'is_form_rendered' ),
	'should_defer()/is_form_rendered() still present'
);
$check(
	'Client-controlled checkout bypass is gone',
	! method_exists( 'GSWP_Gravity_Forms', 'is_form_submission' ),
	'is_form_submission() still present — see v2.17.0'
);

// ---------------------------------------------------------------------------
echo "\n5. Conflict reporting\n";

$conflict = GSWP_Recaptcha_Loader::stored_conflict();
if ( null === $conflict ) {
	echo "  INFO  no conflict recorded (expected on a healthy single-key site)\n";
} else {
	echo '  INFO  conflict recorded, suppressing=' . ( ! empty( $conflict['suppressing'] ) ? 'yes' : 'no' ) . "\n";
	foreach ( $conflict['loaders'] as $loader ) {
		echo '        ' . $loader['handle'] . ' key=' . $loader['key'] . "\n";
	}
}

$check(
	'Conflict hash changes when suppression state changes',
	GSWP_Recaptcha_Loader::conflict_hash( array( array( 'handle' => 'h', 'key' => 'k' ) ), true )
		!== GSWP_Recaptcha_Loader::conflict_hash( array( array( 'handle' => 'h', 'key' => 'k' ) ), false ),
	'a dismissed notice would not re-arm when suppression turns on'
);

// ---------------------------------------------------------------------------
echo "\n=== {$pass} passed, {$fail} failed ===\n";

echo <<<'NOTES'

Browser scenarios to run manually on staging
--------------------------------------------
 1. GF form + Woo checkout on one page, SAME key
    -> exactly one enterprise.js tag in view-source
    -> GF Stripe payment element mounts
    -> Woo checkout completes
 2. As (1) with conflict mode "active"      -> identical to (1); nothing suppressed
 3. As (1) with conflict mode "site"        -> GF loader suppressed, warnings raised
 4a. GF pointed at a DIFFERENT key, mode off
    -> both tags present; dismissible Warning notice; Compatibility panel amber
 4b. Same, mode "active", our reCAPTCHA on the page
    -> GF loader suppressed; NON-dismissible Critical notice; plugins-row notice;
       WooCommerce log line at error level; diagnostic reports suppressing=true
 4c. Dismiss the Warning, then change the foreign key
    -> notice re-arms (dismissal is keyed to the conflict hash)
 5. Woo login/registration on a page containing a GF form
    -> our token fields populate (regression test for the 2.16.0 outage)
 6. Page with a GF form and no WooCommerce -> one loader, GF unaffected, no notice
 7. WooCommerce BLOCKS checkout with a foreign loader present
    -> block script still enqueues (handle registered as a dependency)
    -> Store API request carries extensions.gswp.token
 8. No site key configured -> no token field printed, no enforcement, no fatal
 9. Site key configured, Gravity Forms absent -> unchanged from 2.17.0

NOTES;

echo "\n";
