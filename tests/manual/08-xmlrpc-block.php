<?php
// GSWP test 8/8 (optional) — XML-RPC password block for ENROLLED users
// (the v2.8.0 bug fix: block_non_interactive was never hooked before).
// Self-contained: temp users, simulated XML-RPC context, full cleanup.
if ( defined( 'XMLRPC_REQUEST' ) ) {
	echo "ABORT: already an XML-RPC request; run via the normal MCP PHP tool.\n";
	return;
}
$t = function ( $label, $ok, $d = '' ) { printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $d ? " [{$d}]" : '' ); };
$n    = wp_rand( 1000, 9999 );
$pass = wp_generate_password( 24 );

$enrolled = wp_insert_user( array( 'user_login' => "gswp-xmlrpc-2fa-{$n}", 'user_pass' => $pass, 'user_email' => "gswp-x2fa-{$n}@example.invalid", 'role' => 'subscriber' ) );
$plain    = wp_insert_user( array( 'user_login' => "gswp-xmlrpc-plain-{$n}", 'user_pass' => $pass, 'user_email' => "gswp-xpl-{$n}@example.invalid", 'role' => 'subscriber' ) );
if ( is_wp_error( $enrolled ) || is_wp_error( $plain ) ) { echo "ABORT: could not create temp users.\n"; return; }

// Enrol the first user in 2FA directly (meta only; no login flow needed).
update_user_meta( $enrolled, 'gswp_2fa_enabled', '1' );
update_user_meta( $enrolled, 'gswp_2fa_secret', GSWP_TOTP::generate_secret() );

// Simulate the XML-RPC context for the rest of this request.
define( 'XMLRPC_REQUEST', true );

$r = wp_authenticate( "gswp-xmlrpc-2fa-{$n}", $pass );
$t( 'enrolled user refused over XML-RPC', is_wp_error( $r ) && 'gswp_2fa_required' === $r->get_error_code(), is_wp_error( $r ) ? $r->get_error_code() : 'WP_User!' );

$r = wp_authenticate( "gswp-xmlrpc-plain-{$n}", $pass );
$t( 'non-enrolled user unaffected', $r instanceof WP_User, is_wp_error( $r ) ? $r->get_error_code() : 'ok' );

if ( ! function_exists( 'wp_delete_user' ) ) { require_once ABSPATH . 'wp-admin/includes/user.php'; }
wp_delete_user( $enrolled );
wp_delete_user( $plain );
echo "Cleanup done (temp users removed). XML-RPC test complete.\n";
