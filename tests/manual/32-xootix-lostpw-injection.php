<?php
// GSWP manual test 32 — the Xootix (Login/Signup Popup) lost-password form
// carries a populated-able reCAPTCHA token field, and enforcement still bites
// a submission without one.
//
// Run with: wp eval-file tests/manual/32-xootix-lostpw-injection.php
//
// Requires: the Login/Signup Popup plugin (easy-login-woocommerce) active with
// its popup enabled, a configured site key, and gswp_enable_wp_login,
// gswp_enable_wp_register and gswp_enable_wp_lostpassword all = 1. Run logged
// out is NOT required — the rendered page is fetched over loopback with no
// cookies, so the remote request is a logged-out visitor.
//
// Written for v2.30.1 after the live site refused every popup password reset
// with "Anti-spam verification token is missing". The defect was a map key:
// GSWP_Xootix keyed injection off the lost-password form's wire action
// ('lostPassword', the value of its `_xoo_el_form` hidden input) while the
// plugin's `xoo_el_form_end` template action passes the render slug ('lostpw',
// the basename of templates/global/xoo-el-lostpw-section.php). The field was
// therefore never printed into that form, and validation — correctly wired —
// refused the empty token.
//
// Per the Phase 57 lesson recorded in test 29: assert on the value that
// crosses the wire. So this file asserts on the rendered popup HTML fetched
// over loopback and on a real tokenless admin-ajax POST, not on the presence
// of the PHP meant to put the field there. It also derives the render slugs
// from the INSTALLED Xootix templates, so a future Xootix rename fails loudly
// here instead of silently dropping the field on a live site.

$t = function ( $label, $ok, $d = '' ) {
	printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' );
};

// --- Preflight ---------------------------------------------------------------
if ( ! function_exists( 'xoo_el' ) ) {
	echo "SKIP: easy-login-woocommerce is not active on this site.\n";
	return;
}
foreach ( array( 'gswp_enable_wp_login', 'gswp_enable_wp_register', 'gswp_enable_wp_lostpassword' ) as $opt ) {
	if ( '1' !== get_option( $opt, '0' ) ) {
		echo "SKIP: {$opt} must be 1 for this test.\n";
		return;
	}
}
$t( 'site key configured', '' !== GSWP_Recaptcha_Loader::site_key() );

// --- The render slugs, derived from the installed Xootix templates -----------
// xoo-el-form.php loops the sections and loads global/xoo-el-{$form}-section.php,
// passing the same $form to xoo_el_form_end. The section template basenames ARE
// the slugs the injection side must key off.
$xoo_main  = ( new ReflectionFunction( 'xoo_el' ) )->getFileName();
$xoo_dir   = dirname( $xoo_main );
$section_files = glob( $xoo_dir . '/templates/global/*-section.php' ) ?: array();
$slugs     = array();
foreach ( $section_files as $file ) {
	$slugs[] = str_replace( array( 'xoo-el-', '-section.php' ), '', basename( $file ) );
}
$t( 'installed Xootix ships a lostpw section', in_array( 'lostpw', $slugs, true ), implode( ',', $slugs ) );

$form_template = (string) file_get_contents( $xoo_dir . '/templates/xoo-el-form.php' );
$t(
	'xoo-el-form.php passes the section slug to xoo_el_form_end',
	false !== strpos( $form_template, 'do_action( \'xoo_el_form_end\', $form' )
		&& false !== strpos( $form_template, '\'global/xoo-el-\'.$form.\'-section.php\'' )
);

// Our map must cover every slug we enforce a wire filter for.
$xootix  = new GSWP_Xootix( new GSWP_Verifier() );
$reflect = new ReflectionClass( $xootix );
$prop    = $reflect->getProperty( 'forms' );
$prop->setAccessible( true );
$map = $prop->getValue( $xootix );
foreach ( array( 'login', 'register', 'lostpw' ) as $slug ) {
	$t( "map keyed on render slug '{$slug}'", isset( $map[ $slug ] ) );
}
$t( 'lostpw map entry uses the lostpassword action', isset( $map['lostpw']['action'] ) && 'lostpassword' === $map['lostpw']['action'] );
$t( 'lostPassword wire action aliased', isset( $map['lostPassword'] ) && $map['lostPassword'] === $map['lostpw'] );

// --- The rendered popup: the field is inside each form, on the wire ----------
// Cache-busted so a page cache populated before this deploy cannot answer.
$page = wp_remote_get( add_query_arg( 'gswp32', (string) time(), home_url( '/' ) ), array( 'timeout' => 30 ) );
if ( is_wp_error( $page ) ) {
	echo 'SKIP: loopback request failed: ' . $page->get_error_message() . "\n";
	return;
}
$html = (string) wp_remote_retrieve_body( $page );

$container = '';
if ( preg_match( '/<div class="xoo-el-form-container.*$/s', $html, $m ) ) {
	$container = $m[0];
}
$t( 'popup form container rendered logged-out', '' !== $container );

$section_chunk = function ( $slug ) use ( $container ) {
	foreach ( preg_split( '/(?=<div data-section=")/', $container ) as $chunk ) {
		if ( 0 === strpos( $chunk, '<div data-section="' . $slug . '"' ) ) {
			return $chunk;
		}
	}
	return '';
};

$expected = array(
	'login'    => 'login',
	'register' => 'register',
	'lostpw'   => 'lostpassword',
);
foreach ( $expected as $slug => $action ) {
	$chunk = $section_chunk( $slug );
	$form  = '';
	if ( preg_match( '/<form class="xoo-el-action-form xoo-el-form-' . $slug . '".*?<\/form>/s', $chunk, $m ) ) {
		$form = $m[0];
	}
	$t( "{$slug}: form rendered", '' !== $form );
	$t(
		"{$slug}: token field inside the <form>",
		false !== strpos( $form, 'name="g-recaptcha-response"' )
			&& false !== strpos( $form, 'data-recaptcha-action="' . $action . '"' )
	);
}

// The lostpw section must still carry the wire action its AJAX handler
// dispatches on — the identifier that must NOT be the injection map key.
$lostpw_chunk = $section_chunk( 'lostpw' );
$t(
	'lostpw section carries _xoo_el_form=lostPassword (wire action)',
	false !== strpos( $lostpw_chunk, 'name="_xoo_el_form"' ) && false !== strpos( $lostpw_chunk, 'value="lostPassword"' )
);

// Second stages stay unprotected on purpose: printing a field this plugin
// never reads would break the A4 invariant.
foreach ( array( 'resetpw', 'single' ) as $slug ) {
	$chunk = $section_chunk( $slug );
	if ( '' === $chunk ) {
		continue; // Not rendered by this site's configuration.
	}
	$t( "{$slug}: no token field printed", false === strpos( $chunk, 'name="g-recaptcha-response"' ) );
}

// --- Enforcement: a tokenless bot POST is still refused ----------------------
$bot = wp_remote_post(
	admin_url( 'admin-ajax.php' ),
	array(
		'timeout' => 30,
		'body'    => array(
			'action'     => 'xoo_el_form_action',
			'_xoo_el_form' => 'lostPassword',
			'user_login' => 'gswp-test-no-token',
		),
	)
);
$bot_body = (string) wp_remote_retrieve_body( $bot );
$t(
	'tokenless lostpw POST refused with the missing-token error',
	false !== strpos( $bot_body, 'Anti-spam verification token is missing' ),
	substr( $bot_body, 0, 120 )
);

// --- Negative control: toggles off prints nothing into the popup -------------
$saved = array();
foreach ( array( 'gswp_enable_wp_login', 'gswp_enable_wp_register', 'gswp_enable_wp_lostpassword' ) as $opt ) {
	$saved[ $opt ] = get_option( $opt );
	update_option( $opt, '0' );
}
$off = wp_remote_get( add_query_arg( 'gswp32', (string) time(), home_url( '/' ) ), array( 'timeout' => 30 ) );
foreach ( $saved as $opt => $val ) {
	update_option( $opt, $val );
}
if ( is_wp_error( $off ) ) {
	echo 'SKIP: negative-control loopback request failed: ' . $off->get_error_message() . "\n";
	return;
}
$off_html = (string) wp_remote_retrieve_body( $off );
$off_container = '';
if ( preg_match( '/<div class="xoo-el-form-container.*$/s', $off_html, $m ) ) {
	$off_container = $m[0];
}
$t(
	'toggles off: no token field anywhere in the popup',
	'' === $off_container || false === strpos( $off_container, 'name="g-recaptcha-response"' )
);

echo "Done. Live checks still outstanding: submit a real popup reset (email must\narrive), repeat it immediately (no DUPE), and re-run popup login/register.\n";
