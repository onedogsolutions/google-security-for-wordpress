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

// With no site key, nothing should be printed.
$original_key = get_option( 'gswp_site_key', '' );
update_option( 'gswp_site_key', '' );

ob_start();
do_action( 'show_user_profile', wp_get_current_user() );
$empty_profile = ob_get_clean();
$t( 'no field when site key unset', '' === $empty_profile );

update_option( 'gswp_site_key', $original_key );

echo "Password reset asset test complete.\n";
