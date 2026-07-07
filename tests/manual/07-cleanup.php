<?php
// GSWP app-password test 7/7 — cleanup. Idempotent: safe to run at ANY point,
// including after a failure. Restores options, deletes temp users/role/state.
$S = get_option( 'gswp_apw_test_state' );
if ( ! $S ) {
	echo "Nothing to clean: no test state found.\n";
	return;
}

foreach ( $S['snapshot'] as $opt => $val ) {
	if ( false === $val ) {
		delete_option( $opt );
	} else {
		update_option( $opt, $val );
	}
	echo "restored {$opt} = " . var_export( $val, true ) . "\n";
}

if ( ! function_exists( 'wp_delete_user' ) ) {
	require_once ABSPATH . 'wp-admin/includes/user.php';
}
foreach ( array( 'a_id', 'b_id' ) as $k ) {
	if ( ! empty( $S[ $k ] ) && get_user_by( 'id', $S[ $k ] ) ) {
		wp_delete_user( $S[ $k ] );
		echo "deleted user #{$S[ $k ]}\n";
	}
}
remove_role( 'gswp_test_role' );
delete_option( 'gswp_apw_test_state' );
echo "CLEANUP OK — options restored, temp users/role/state removed.\n";
