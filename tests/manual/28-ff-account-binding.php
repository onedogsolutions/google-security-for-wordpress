<?php
/**
 * Fluent Forms replacement verification - chunk 28: account binding (v2.23.2)
 *
 * D2 ONLY, and deliberately tiny.
 *
 * Chunk 24 answers this too, inside a much larger report. On the reporting
 * site chunk 24 failed repeatedly between tools while every other chunk ran,
 * and the reported error pointed at its user_registration_feeds loop twice.
 * That loop did contain a real fragility - a phpcs:ignore comment sitting in
 * the middle of a multi-line concatenation, valid PHP but destroyed by any
 * layer that reflows or joins lines, which swallows the continuation into the
 * comment. It has been fixed there, but D2 is the last unconfirmed binding in
 * this release and it should not stay blocked on whether a 290-line file
 * survives a copy-paste.
 *
 * So: no non-ASCII characters, no comments inside any expression, no tables,
 * nothing clever. It answers one question.
 *
 * THE QUESTION. Fluent Forms Pro stores BOTH User Registration and User
 * Update feeds under one meta_key, 'user_registration_feeds', and tells them
 * apart with the 'list_id' key inside the feed JSON - VERIFIED against
 * UserUpdateFormHandler::isValidFeed(). The 2.23.0/2.23.1 provider guessed
 * four key names that do not exist, so it read every User Update feed as a
 * registration feed: a profile-edit form became STRICT and rejected a
 * signed-in visitor on a missing token. That is the Phase 48 incident,
 * reproduced. This confirms the fix against a real form.
 *
 * Read-only. Writes nothing.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo "=== CHUNK 28: ACCOUNT BINDING (D2) ===\n";
echo '  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ) . "\n";
echo '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ) . "\n";
echo '  current user   : ' . ( is_user_logged_in() ? 'logged IN (id ' . get_current_user_id() . ')' : 'logged OUT' ) . "\n\n";

if ( ! class_exists( 'GSWP_Provider_Fluent_Forms' ) ) {
	echo "STOP: plugin not active or older than 2.23.0.\n";
	return;
}

$provider = GSWP_Form_Provider_Registry::get( 'fluent-forms' );

if ( ! $provider || ! $provider->is_active() ) {
	echo "STOP: Fluent Forms is not active.\n";
	return;
}

global $wpdb;

$meta_table = $wpdb->prefix . 'fluentform_form_meta';
$found_any  = false;

foreach ( $provider->forms() as $form_id => $title ) {

	$sql = $wpdb->prepare(
		"SELECT meta_key, value FROM {$meta_table} WHERE form_id = %d AND meta_key IN ('user_registration_feeds','_has_user_registration','_has_user_update')",
		(int) $form_id
	);

	// phpcs:ignore WordPress.DB
	$rows = $wpdb->get_results( $sql, ARRAY_A );

	if ( empty( $rows ) ) {
		continue;
	}

	$found_any = true;

	echo '--- form #' . $form_id . ': ' . $title . "\n";

	foreach ( $rows as $row ) {

		$key = (string) $row['meta_key'];
		$val = (string) $row['value'];

		if ( 'user_registration_feeds' !== $key ) {
			echo '    ' . $key . ' = ' . $val . "   [sticky flag, fallback only]\n";
			continue;
		}

		$feed = json_decode( $val, true );

		if ( ! is_array( $feed ) ) {
			echo "    FEED ROW: could not decode JSON - provider treats this as 'create'\n";
			continue;
		}

		$list_id = isset( $feed['list_id'] ) ? $feed['list_id'] : '(absent)';
		$enabled = array_key_exists( 'enabled', $feed ) ? $feed['enabled'] : '(absent)';
		$expect  = ( 'user_update' === $list_id ) ? 'update' : 'create';

		if ( is_bool( $enabled ) ) {
			$enabled = $enabled ? 'true' : 'false';
		}

		echo '    FEED ROW: list_id=' . $list_id . '  enabled=' . $enabled . '  -> expect ' . $expect . "\n";
	}

	$policy  = method_exists( $provider, 'form_policy' ) ? $provider->form_policy( $form_id ) : array();
	$account = isset( $policy['account'] ) && '' !== $policy['account'] ? $policy['account'] : '(none)';
	$action  = isset( $policy['action'] ) ? $policy['action'] : '?';
	$strict  = $provider->form_is_strict( $form_id ) ? 'YES' : 'no';

	echo '    PROVIDER SAYS: account=' . $account . '  action=' . $action . '  STRICT=' . $strict . "\n\n";
}

if ( ! $found_any ) {
	echo "No form on this site has a user_registration_feeds row or a\n";
	echo "_has_user_* flag. D2 cannot be confirmed here - the account binding\n";
	echo "is never exercised. Create a User Update form (Fluent Forms ->\n";
	echo "Settings & Integrations -> User Registration or Update -> list_id\n";
	echo "'User Update'), SAVE THE FEED, then re-run.\n";
	return;
}

echo "=== WHAT TO CHECK ===\n";
echo "  Every FEED ROW's 'expect' must match the PROVIDER SAYS 'account' for\n";
echo "  that form. A form whose only active feed is list_id=user_update must\n";
echo "  read account=update and STRICT=no.\n\n";
echo "  account=create and STRICT=YES on a pure profile-edit form is the\n";
echo "  Phase 48 regression: a signed-in visitor editing her own profile is\n";
echo "  rejected as a spam signup whenever her token is missing or stale.\n";
echo "  Report it and do not rely on the provider for account forms.\n\n";
echo "  A form carrying BOTH an enabled registration feed and an enabled\n";
echo "  update feed is expected to read create when this is run logged OUT\n";
echo "  and update when run logged IN, mirroring Fluent Forms' own gate. One\n";
echo "  feed kind only means one run is enough.\n";

echo "\nReport the whole block above verbatim.\n";
