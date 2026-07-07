<?php
// GSWP app-password test 5/7 — Phase 3: block ON, user B exempted.
$S = get_option( 'gswp_apw_test_state' );
if ( ! $S ) { echo "ABORT: run 02-setup first.\n"; return; }
add_filter( 'application_password_is_api_request', '__return_true' );
add_filter( 'wp_is_application_passwords_available', '__return_true' );
$auth = function ( $l, $p ) { $r = wp_authenticate_application_password( null, $l, $p ); return $r instanceof WP_User ? 'ok' : ( is_wp_error( $r ) ? $r->get_error_code() : 'passthrough' ); };
$t = function ( $label, $ok, $d = '' ) { printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' ); };

update_option( 'gswp_2fa_block_app_passwords', '1' );
update_option( 'gswp_2fa_app_password_exempt_users', $S['b_login'] );

$t( 'exempt user B availability true again', true === wp_is_application_passwords_available_for_user( get_user_by( 'id', $S['b_id'] ) ) );
$r = $auth( $S['b_login'], $S['b_pw'] );
$t( 'exempt user B authenticates', 'ok' === $r, $r );
$r = $auth( $S['a_login'], $S['a_pw'] );
$t( 'non-exempt user A still refused', 'ok' !== $r, $r );
echo "Phase 3 done — run 06 next.\n";
