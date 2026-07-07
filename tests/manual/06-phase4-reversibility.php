<?php
// GSWP app-password test 6/7 — Phase 4: block OFF again → original password
// works with no re-issue (rejected, not revoked).
$S = get_option( 'gswp_apw_test_state' );
if ( ! $S ) { echo "ABORT: run 02-setup first.\n"; return; }
add_filter( 'application_password_is_api_request', '__return_true' );
add_filter( 'wp_is_application_passwords_available', '__return_true' );
$auth = function ( $l, $p ) { $r = wp_authenticate_application_password( null, $l, $p ); return $r instanceof WP_User ? 'ok' : ( is_wp_error( $r ) ? $r->get_error_code() : 'passthrough' ); };
$t = function ( $label, $ok, $d = '' ) { printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' ); };

update_option( 'gswp_2fa_block_app_passwords', '0' );
update_option( 'gswp_2fa_app_password_exempt_users', '' );

$r = $auth( $S['a_login'], $S['a_pw'] );
$t( 'user A ORIGINAL password works, no re-issue needed', 'ok' === $r, $r );
echo "Phase 4 done — run 07-cleanup to finish.\n";
