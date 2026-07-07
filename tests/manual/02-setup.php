<?php
// GSWP app-password test 2/7 — setup fixtures.
// Creates throwaway role + 2 users + app passwords; snapshots the options it
// will change. State persists in the gswp_apw_test_state option (07 deletes it).
if ( get_option( 'gswp_apw_test_state' ) ) {
	echo "ABORT: leftover state found — run 07-cleanup first.\n";
	return;
}

$snapshot = array(
	'gswp_2fa_block_app_passwords'       => get_option( 'gswp_2fa_block_app_passwords' ),
	'gswp_2fa_app_password_exempt_users' => get_option( 'gswp_2fa_app_password_exempt_users' ),
	'gswp_2fa_enforced_roles'            => get_option( 'gswp_2fa_enforced_roles' ),
);

add_role( 'gswp_test_role', 'GSWP Test Role', array( 'read' => true ) );
$n = wp_rand( 1000, 9999 );
$a = wp_insert_user( array( 'user_login' => "gswp-blocked-{$n}", 'user_pass' => wp_generate_password( 24 ), 'user_email' => "gswp-blocked-{$n}@example.invalid", 'role' => 'gswp_test_role' ) );
$b = wp_insert_user( array( 'user_login' => "gswp-exempt-{$n}", 'user_pass' => wp_generate_password( 24 ), 'user_email' => "gswp-exempt-{$n}@example.invalid", 'role' => 'gswp_test_role' ) );
if ( is_wp_error( $a ) || is_wp_error( $b ) ) {
	echo "ABORT: could not create temp users.\n";
	return;
}

// Enforce ONLY the throwaway role; block off; app passwords made while off.
update_option( 'gswp_2fa_enforced_roles', array( 'gswp_test_role' ) );
update_option( 'gswp_2fa_block_app_passwords', '0' );
update_option( 'gswp_2fa_app_password_exempt_users', '' );

$pa = WP_Application_Passwords::create_new_application_password( $a, array( 'name' => 'gswp-test' ) );
$pb = WP_Application_Passwords::create_new_application_password( $b, array( 'name' => 'gswp-test' ) );
if ( is_wp_error( $pa ) || is_wp_error( $pb ) ) {
	echo 'ABORT: app-password creation failed: ' . ( is_wp_error( $pa ) ? $pa->get_error_message() : $pb->get_error_message() ) . "\n";
	return;
}

update_option( 'gswp_apw_test_state', array(
	'snapshot' => $snapshot,
	'a_id'     => $a, 'a_login' => "gswp-blocked-{$n}", 'a_pw' => $pa[0],
	'b_id'     => $b, 'b_login' => "gswp-exempt-{$n}",  'b_pw' => $pb[0],
), false );

echo "SETUP OK — users gswp-blocked-{$n} + gswp-exempt-{$n} created in gswp_test_role (the only enforced role). Run 03 next.\n";
