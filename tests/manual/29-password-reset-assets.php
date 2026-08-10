<?php
// GSWP manual test 29 — admin-initiated password resets are exempt from token
// enforcement, and the public lost-password form is not.
//
// Run with: wp eval-file tests/manual/29-password-reset-assets.php
//
// Requires a configured site key and gswp_enable_wp_lostpassword = 1, and must
// run as a user with edit_users (wp --user=<admin>).
//
// Rewritten for v2.27.3. The previous version of this file asserted that the
// admin token field, the admin reCAPTCHA enqueue and the admin XHR-patching
// inline script were all present. Every one of those assertions passed against
// code that could not send a password reset link at all, because they checked
// that the machinery existed rather than that it delivered a token. One of them
// asserted the inline script "targets send_password_reset" — the PHP handler
// name, which never appears in a request body; the wire action is
// send-password-reset. That assertion is why the defect shipped three times.
//
// The lesson is recorded here rather than in a commit message: assert on the
// value that crosses the wire, not on the presence of the code meant to put it
// there.

$t = function ( $label, $ok, $d = '' ) {
	printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' );
};

$login    = GSWP_Login::class;
$instance = new GSWP_Login( new GSWP_Verifier() );

$reflect = new ReflectionClass( $login );
$call    = function ( $method ) use ( $reflect, $instance ) {
	$m = $reflect->getMethod( $method );
	$m->setAccessible( true );
	return $m->invoke( $instance );
};

// --- The admin machinery is gone -------------------------------------------
// These hooks and methods existed in 2.26.2-2.27.2 to carry a token into
// wp-admin. None of them could work (see PLAN-admin-password-reset.md), and
// leaving them would print a field this plugin no longer reads — the A4
// invariant in the wrong direction.
foreach ( array( 'enqueue_admin_assets', 'inject_admin_reset_field', 'inject_admin_users_field', 'print_admin_reset_inline_js' ) as $gone ) {
	$t( "{$gone}() removed", ! method_exists( $login, $gone ) );
}
$t( 'no admin_enqueue_scripts hook', false === has_action( 'admin_enqueue_scripts', array( $login, 'enqueue_admin_assets' ) ) );
$t( 'no restrict_manage_users hook', false === has_action( 'restrict_manage_users', array( $login, 'inject_admin_users_field' ) ) );
$t( 'no admin_footer inline JS hook', false === has_action( 'admin_footer', array( $login, 'print_admin_reset_inline_js' ) ) );

// The shared bootstrap stays hooked in wp-admin: it is inert unless some other
// integration requests it, and removing it would regress any that does.
$t(
	'shared bootstrap still hooked in wp-admin',
	false !== has_action( 'admin_print_footer_scripts', array( GSWP_Recaptcha_Loader::class, 'print_bootstrap' ) )
);

// --- The exemption recognises each admin entry point ------------------------
$admin_id = get_current_user_id();
$target   = 0;
foreach ( get_users( array( 'exclude' => array( $admin_id ), 'number' => 1, 'fields' => 'ID' ) ) as $id ) {
	$target = (int) $id;
}

$saved = array( $_GET, $_POST, $_REQUEST, $GLOBALS['pagenow'] ?? null );
$reset_superglobals = function () {
	$_GET     = array();
	$_POST    = array();
	$_REQUEST = array();
};

// 1. users.php per-row link: users.php?action=resetpassword&users=ID
$reset_superglobals();
$GLOBALS['pagenow'] = 'users.php';
$_REQUEST           = array(
	'action'   => 'resetpassword',
	'users'    => (string) $target,
	'_wpnonce' => wp_create_nonce( 'bulk-users' ),
);
$_GET = $_REQUEST;
$t( 'users.php row action exempt', true === $call( 'is_users_screen_reset' ) );

// 2. users.php bulk action from the bottom of the table uses action2.
$_REQUEST['action']  = '-1';
$_REQUEST['action2'] = 'resetpassword';
$_GET                = $_REQUEST;
$t( 'users.php bulk action2 exempt', true === $call( 'is_users_screen_reset' ) );

// 3. A forged nonce must NOT be exempt — this is the check that keeps the
//    exemption from being a bypass.
$_REQUEST['_wpnonce'] = 'not-a-real-nonce';
$_GET                 = $_REQUEST;
$t( 'users.php bad nonce NOT exempt', false === $call( 'is_users_screen_reset' ) );

// 4. Right nonce, wrong action: an unrelated bulk action is not a reset.
$_REQUEST['_wpnonce'] = wp_create_nonce( 'bulk-users' );
$_REQUEST['action']   = 'delete';
$_REQUEST['action2']  = '-1';
$_GET                 = $_REQUEST;
$t( 'users.php non-reset action NOT exempt', false === $call( 'is_users_screen_reset' ) );

// 5. Same parameters on a screen that is not users.php.
$_REQUEST['action']  = 'resetpassword';
$_GET                = $_REQUEST;
$GLOBALS['pagenow']  = 'wp-login.php';
$t( 'non-users.php screen NOT exempt', false === $call( 'is_users_screen_reset' ) );

// 6. Profile "Send Reset Link" AJAX. Note the hyphenated action name: core
//    registers AJAX actions hyphenated in admin-ajax.php and derives the PHP
//    handler name with str_replace( '-', '_' ).
$reset_superglobals();
$GLOBALS['pagenow'] = 'admin-ajax.php';
$_POST              = array(
	'action'  => 'send-password-reset',
	'user_id' => (string) $target,
	'nonce'   => wp_create_nonce( 'reset-password-for-' . $target ),
);
$_REQUEST = $_POST;
$t( 'profile AJAX reset exempt', true === $call( 'is_profile_reset_ajax' ), "target user {$target}" );

// 7. The underscore spelling is the PHP function name, not a wire action. It
//    must not satisfy the exemption.
$_POST['action'] = 'send_password_reset';
$_REQUEST        = $_POST;
$t( 'underscore action NOT exempt', false === $call( 'is_profile_reset_ajax' ) );

// 8. Correct action, nonce minted for a different user.
$_POST['action'] = 'send-password-reset';
$_POST['nonce']  = wp_create_nonce( 'reset-password-for-' . ( $target + 1000 ) );
$_REQUEST        = $_POST;
$t( 'profile AJAX wrong-user nonce NOT exempt', false === $call( 'is_profile_reset_ajax' ) );

// 9. The public lost-password form satisfies neither branch, so it stays
//    enforced. This is the regression that must never pass silently.
$reset_superglobals();
$GLOBALS['pagenow']            = 'wp-login.php';
$_POST['user_login']           = 'someone';
$_POST['g-recaptcha-response'] = 'a-token';
$_REQUEST                      = $_POST;
$t( 'public lost-password NOT exempt', false === $call( 'is_admin_initiated_reset' ) );

list( $_GET, $_POST, $_REQUEST, $GLOBALS['pagenow'] ) = $saved;

// --- Verifier token cache ---------------------------------------------------
$verifier = new ReflectionClass( GSWP_Verifier::class );
$t( 'verifier declares token_cache property', $verifier->hasProperty( 'token_cache' ) );

if ( $verifier->hasProperty( 'token_cache' ) ) {
	$prop = $verifier->getProperty( 'token_cache' );
	$prop->setAccessible( true );
	$v = new GSWP_Verifier();
	$t( 'token_cache initialises as empty array', is_array( $prop->getValue( $v ) ) && empty( $prop->getValue( $v ) ) );

	// The cache key must carry the context and expected action, not just the
	// token: a cache hit re-runs neither the action check nor the threshold.
	$src = file_get_contents( GSWP_PLUGIN_DIR . 'includes/class-gswp-verifier.php' );
	$t(
		'token_cache keyed on token + context + action',
		false !== strpos( $src, "\$cache_key = \$token . '|' . \$context . '|'" )
		&& false === strpos( $src, '$this->token_cache[ $token ]' )
	);
}

// --- PowerPack front-end lost password (unchanged by this phase) ------------
if ( class_exists( 'BB_PowerPack' ) ) {
	if ( ! class_exists( 'PPLoginFormModule' ) ) {
		class PPLoginFormModule {}
	}

	$pp          = new GSWP_Powerpack( new GSWP_Verifier() );
	$module      = new PPLoginFormModule();
	$module_html = '<div class="pp-login-form-field pp-field-group pp-field-type-recaptcha">captcha</div></div>';

	$pp->replace_module_recaptcha( $module_html, $module );

	ob_start();
	$pp->print_inline_js();
	$pp_inline_js = ob_get_clean();
	$t( 'PowerPack prefilter includes lost-password action', false !== strpos( $pp_inline_js, 'pp_lf_process_lost_pass' ) );
	$t( 'PowerPack click handler targets lost-password button', false !== strpos( $pp_inline_js, '.pp-login-form--button' ) );
} else {
	$t( 'PowerPack prefilter includes lost-password action', true, 'PowerPack not active' );
}

// --- Front-end field still renders -----------------------------------------
ob_start();
do_action( 'lostpassword_form' );
$front_html = ob_get_clean();
$t(
	'front-end lost-password field present',
	false !== strpos( $front_html, 'name="g-recaptcha-response"' )
	&& false !== strpos( $front_html, 'data-recaptcha-action="lostpassword"' )
);

// With no site key, nothing should be printed.
$original_key = get_option( 'gswp_site_key', '' );
update_option( 'gswp_site_key', '' );

ob_start();
do_action( 'lostpassword_form' );
$empty_front = ob_get_clean();
$t( 'no field when site key unset', '' === $empty_front );

update_option( 'gswp_site_key', $original_key );

echo "Password reset exemption test complete.\n";
echo "NOTE: this file proves the server-side gate only. The six live checks in\n";
echo "PLAN-admin-password-reset.md section 7 are what confirm a reset email is\n";
echo "actually sent; no assertion here can substitute for them.\n";
