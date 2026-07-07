<?php
// GSWP app-password test 4/7 — Phase 2: block ON, no exemptions → refused.
$S = get_option( 'gswp_apw_test_state' );
if ( ! $S ) { echo "ABORT: run 02-setup first.\n"; return; }
add_filter( 'application_password_is_api_request', '__return_true' );
add_filter( 'wp_is_application_passwords_available', '__return_true' );
$auth = function ( $l, $p ) { $r = wp_authenticate_application_password( null, $l, $p ); return $r instanceof WP_User ? 'ok' : ( is_wp_error( $r ) ? $r->get_error_code() : 'passthrough' ); };
$t = function ( $label, $ok, $d = '' ) { printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' ); };

update_option( 'gswp_2fa_block_app_passwords', '1' );
update_option( 'gswp_2fa_app_password_exempt_users', '' );

$t( 'user A availability false', false === wp_is_application_passwords_available_for_user( get_user_by( 'id', $S['a_id'] ) ) );
$r = $auth( $S['a_login'], $S['a_pw'] );
$t( 'user A refused with disabled_for_user', 'application_passwords_disabled_for_user' === $r, $r );
$r = $auth( $S['b_login'], $S['b_pw'] );
$t( 'user B refused too', 'ok' !== $r, $r );
if ( get_current_user_id() ) {
	$t( 'connecting account (this MCP session) unaffected', true === wp_is_application_passwords_available_for_user( wp_get_current_user() ), wp_get_current_user()->user_login );
}
echo "Phase 2 done — run 05 next.\n";
