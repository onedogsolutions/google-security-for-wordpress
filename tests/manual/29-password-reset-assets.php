<?php
// GSWP manual test 29 — verify reCAPTCHA assets and token fields are present
// for admin-initiated password reset flows.
//
// Run with: wp eval-file tests/manual/29-password-reset-assets.php
//
// Requires a configured site key and gswp_enable_wp_lostpassword = 1.

$t = function ( $label, $ok, $d = '' ) {
	printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' );
};

$login = GSWP_Login::class;

// Ensure the new hooks are wired.
$t( 'admin_enqueue_scripts hooked', false !== has_action( 'admin_enqueue_scripts', array( $login, 'enqueue_admin_assets' ) ) );
$t( 'show_user_profile hooked', false !== has_action( 'show_user_profile', array( $login, 'inject_admin_reset_field' ) ) );
$t( 'edit_user_profile hooked', false !== has_action( 'edit_user_profile', array( $login, 'inject_admin_reset_field' ) ) );
$t( 'restrict_manage_users hooked', false !== has_action( 'restrict_manage_users', array( $login, 'inject_admin_users_field' ) ) );
$t( 'admin_footer reset prefilter hooked', false !== has_action( 'admin_footer', array( $login, 'print_admin_reset_inline_js' ) ) );

// Confirm the field shape on profile screens.
ob_start();
do_action( 'show_user_profile', wp_get_current_user() );
$profile_html = ob_get_clean();
$t(
	'profile field present',
	false !== strpos( $profile_html, 'name="g-recaptcha-response"' )
	&& false !== strpos( $profile_html, 'data-recaptcha-action="lostpassword"' )
);

// Confirm the field shape on the Users screen bulk-action form.
ob_start();
do_action( 'restrict_manage_users', 'top' );
$users_html = ob_get_clean();
$t(
	'users.php field present',
	false !== strpos( $users_html, 'name="g-recaptcha-response"' )
	&& false !== strpos( $users_html, 'data-recaptcha-action="lostpassword"' )
);

// restrict_manage_users runs twice (top/bottom); the static flag should prevent
// a second field.
ob_start();
do_action( 'restrict_manage_users', 'bottom' );
$users_html_bottom = ob_get_clean();
$t( 'users.php field printed once only', '' === $users_html_bottom );

// Confirm the API script is enqueued on each relevant admin screen.
foreach ( array( 'users.php', 'user-edit.php', 'profile.php' ) as $hook ) {
	wp_dequeue_script( GSWP_Recaptcha_Loader::HANDLE );
	do_action( 'admin_enqueue_scripts', $hook );
	$t( "{$hook} enqueues API script", wp_script_is( GSWP_Recaptcha_Loader::HANDLE, 'enqueued' ), $hook );
}

// Confirm the admin "Send Reset Link" prefilter script is emitted.
$login_instance = new GSWP_Login( new GSWP_Verifier() );
ob_start();
$login_instance->print_admin_reset_inline_js();
$admin_inline_js = ob_get_clean();
$t(
	'admin reset prefilter targets send_password_reset',
	false !== strpos( $admin_inline_js, 'send_password_reset' )
);

// Confirm the PowerPack lost-password action is included in the front-end
// prefilter when the Login Form module is rendered.
if ( class_exists( 'BB_PowerPack' ) ) {
	if ( ! class_exists( 'PPLoginFormModule' ) ) {
		class PPLoginFormModule {}
	}

	$pp      = new GSWP_Powerpack( new GSWP_Verifier() );
	$module  = new PPLoginFormModule();
	$module_html = '<div class="pp-login-form-field pp-field-group pp-field-type-recaptcha">captcha</div></div>';

	$pp->replace_module_recaptcha( $module_html, $module );

	ob_start();
	$pp->print_inline_js();
	$pp_inline_js = ob_get_clean();
	$t(
		'PowerPack prefilter includes lost-password action',
		false !== strpos( $pp_inline_js, 'pp_lf_process_lost_pass' )
	);
} else {
	$t( 'PowerPack prefilter includes lost-password action', true, 'PowerPack not active' );
}

// With no site key, nothing should be printed.
$original_key = get_option( 'gswp_site_key', '' );
update_option( 'gswp_site_key', '' );

ob_start();
do_action( 'show_user_profile', wp_get_current_user() );
$empty_profile = ob_get_clean();
$t( 'no field when site key unset', '' === $empty_profile );

update_option( 'gswp_site_key', $original_key );

echo "Password reset asset test complete.\n";
