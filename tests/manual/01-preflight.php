<?php
// GSWP app-password test 1/7 — preflight. Read-only.
echo 'Site: ' . home_url() . ' | WP ' . get_bloginfo( 'version' ) . "\n";
echo 'Plugin version: ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT LOADED' ) . "\n";
echo 'Connected as: ' . ( get_current_user_id() ? wp_get_current_user()->user_login : '(no user)' ) . "\n";

if ( ! class_exists( 'GSWP_Two_Factor' ) || version_compare( GSWP_VERSION, '2.8.0', '<' ) ) {
	echo "ABORT: plugin not active or older than 2.8.0.\n";
	return;
}
echo '2FA master switch: ' . ( GSWP_Two_Factor::is_feature_enabled() ? 'ON' : 'OFF (ABORT: enable it, then re-run)' ) . "\n";
echo 'App-password filter hooked: ' . ( has_filter( 'wp_is_application_passwords_available_for_user' ) ? 'YES' : 'NO (ABORT: not the 2.8.0 build?)' ) . "\n";
echo 'Block option now: ' . var_export( get_option( 'gswp_2fa_block_app_passwords' ), true ) . "\n";
echo 'Exempt list now: ' . var_export( get_option( 'gswp_2fa_app_password_exempt_users' ), true ) . "\n";
echo "PREFLIGHT OK — run 02-setup next.\n";
