<?php
/**
 * Fluent Forms replacement verification — chunk 24: classification (v2.23.2)
 *
 * Settles how each form is classified, and prints the raw evidence beside the
 * conclusion so a wrong conclusion is visible rather than merely wrong.
 *
 * Classification decides three things that reach a visitor:
 *
 *   - whether a missing token REJECTS the submission or admits and flags it;
 *   - which reCAPTCHA action the token is minted with and checked against;
 *   - which score threshold applies.
 *
 * THE ACCOUNT BINDING IS THE ONE THIS RELEASE EXISTS TO FIX. Fluent Forms
 * Pro stores BOTH User Registration and User Update feeds under a single
 * fluentform_form_meta row, meta_key 'user_registration_feeds', and
 * discriminates between them with the 'list_id' key inside the feed's JSON
 * value ('user_update' vs. everything else) — VERIFIED against
 * UserUpdateFormHandler::isValidFeed() in Fluent Forms Pro 6.2.7.
 *
 * A prior version of this provider scanned for a meta_key CONTAINING
 * 'user_registration' or 'user_update' and guessed the discriminator from
 * four key names that do not exist anywhere in Fluent Forms. Because both
 * feed kinds share the same meta_key, that scan read a User Update feed's
 * row as a registration feed on EVERY install: a signed-in visitor editing
 * her own profile through a Fluent Forms User Update form was classified as
 * account-CREATION, made STRICT, and rejected on a missing or stale token —
 * word for word the Phase 48 incident this whole suite exists to prevent,
 * shipped in the provider that was supposed to prevent it. This chunk is
 * how that gets confirmed fixed.
 *
 * `_has_user_registration` / `_has_user_update` (which Fluent Forms core
 * itself reads to gate its own validation) are printed too, and are used by
 * the provider only as a fallback when no feed row can be decoded — they
 * are STICKY (written when a feed is saved, never cleared) and blind to
 * `enabled`, so they over-report and must not be the primary signal.
 *
 * Read-only.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo "=== RUN CONTEXT ===\n";
echo '  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ) . "\n";
echo '  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ) . "\n";
echo '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ) . "\n";
echo '  current user   : ' . ( is_user_logged_in() ? 'logged in (ID ' . get_current_user_id() . ')' : 'logged out' ) . "\n\n";

if ( ! class_exists( 'GSWP_Provider_Fluent_Forms' ) ) {
	echo "STOP: plugin not active or older than 2.23.0.\n";
	return;
}

$provider = GSWP_Form_Provider_Registry::get( 'fluent-forms' );
if ( ! $provider || ! $provider->is_active() ) {
	echo "STOP: Fluent Forms is not active on this site.\n";
	return;
}

global $wpdb;
$forms_table = $wpdb->prefix . 'fluentform_forms';
$meta_table  = $wpdb->prefix . 'fluentform_form_meta';

$has_meta_table = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $meta_table ) ) === $meta_table; // phpcs:ignore WordPress.DB

echo "  NOTE: account_feed_type() resolves differently for a logged-in visitor\n";
echo "  than a logged-out one, ONLY when a form carries both an active\n";
echo "  registration feed and an active update feed. Run this chunk once\n";
echo "  logged OUT and once logged IN (as any user) if such a form exists, and\n";
echo "  compare the ACCOUNT column between the two runs.\n\n";

// ---------------------------------------------------------------------------
// The conclusions.
// ---------------------------------------------------------------------------
echo "=== CLASSIFICATION ===\n\n";
printf(
	"  %-4s %-26s %-4s %-8s %-8s %-6s %-16s %s\n",
	'ID',
	'TITLE',
	'PAY',
	'ACCOUNT',
	'PASSWORD',
	'STRICT',
	'ACTION',
	'THRESHOLD CONTEXT'
);
echo '  ' . str_repeat( '-', 104 ) . "\n";

foreach ( $provider->forms() as $form_id => $title ) {
	$policy = method_exists( $provider, 'form_policy' ) ? $provider->form_policy( $form_id ) : array();

	printf(
		"  %-4s %-26s %-4s %-8s %-8s %-6s %-16s %s\n",
		$form_id,
		substr( (string) $title, 0, 25 ),
		$provider->form_has_payment( $form_id ) ? 'yes' : '—',
		'' === ( isset( $policy['account'] ) ? $policy['account'] : '' ) ? '—' : $policy['account'],
		! empty( $policy['password'] ) ? 'yes' : '—',
		$provider->form_is_strict( $form_id ) ? 'YES' : '—',
		isset( $policy['action'] ) ? $policy['action'] : '?',
		isset( $policy['context'] ) ? 'gswp_threshold_' . $policy['context'] : '?'
	);
}

echo "\n  STRICT = a submission with no token is REJECTED. Everything else is\n";
echo "  admitted and flagged. Check every STRICT row is one you would want to\n";
echo "  fail closed, and every non-STRICT row is one you would not.\n";
echo "\n  *** THE REGRESSION CHECK: any form that is a pure profile-EDIT form\n";
echo "  (a User Update feed, no User Registration feed) MUST show ACCOUNT =\n";
echo "  update, not create. If it shows 'create', account_feed_type() has\n";
echo "  regressed and a signed-in visitor editing her own profile will be\n";
echo "  rejected as a spam signup on a missing token. ***\n";

// ---------------------------------------------------------------------------
// The evidence: has_payment, field elements, and every meta row — with the
// verified account-feed shape called out explicitly rather than left for the
// reader to notice among the general meta dump.
// ---------------------------------------------------------------------------
echo "\n=== RAW EVIDENCE (this is what settles the bindings) ===\n";

foreach ( $provider->forms() as $form_id => $title ) {
	echo "\n  --- form #{$form_id}: " . substr( (string) $title, 0, 40 ) . " ---\n";

	$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$forms_table} WHERE id = %d", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB

	if ( ! is_array( $row ) ) {
		echo "    form row unreadable.\n";
		continue;
	}

	echo '    has_payment column : ' . ( array_key_exists( 'has_payment', $row ) ? var_export( $row['has_payment'], true ) : 'COLUMN ABSENT' ) . "\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions

	// Field elements, in order, deduplicated with counts.
	$decoded  = json_decode( isset( $row['form_fields'] ) ? (string) $row['form_fields'] : '', true );
	$elements = array();

	$walk = function ( $fields, &$out, $depth = 0 ) use ( &$walk ) {
		if ( $depth > 10 || ! is_array( $fields ) ) {
			return;
		}
		foreach ( $fields as $field ) {
			if ( ! is_array( $field ) ) {
				continue;
			}
			if ( ! empty( $field['element'] ) ) {
				$name = (string) $field['element'];
				$out[ $name ] = isset( $out[ $name ] ) ? $out[ $name ] + 1 : 1;
			}
			if ( ! empty( $field['columns'] ) && is_array( $field['columns'] ) ) {
				foreach ( $field['columns'] as $column ) {
					if ( isset( $column['fields'] ) ) {
						$walk( $column['fields'], $out, $depth + 1 );
					}
				}
			}
			if ( ! empty( $field['fields'] ) && is_array( $field['fields'] ) ) {
				$walk( $field['fields'], $out, $depth + 1 );
			}
		}
	};

	if ( is_array( $decoded ) && isset( $decoded['fields'] ) ) {
		$walk( $decoded['fields'], $elements );
	}

	if ( empty( $elements ) ) {
		echo "    field elements     : NONE PARSED — form_fields JSON did not decode.\n";
		echo "                         The provider treats an unparseable form as a\n";
		echo "                         PAYMENT form, which fails closed. If this row\n";
		echo "                         is not a payment form, report it.\n";
	} else {
		echo "    field elements     : \n";
		foreach ( $elements as $element => $count ) {
			echo '                         ' . str_pad( $element, 34 ) . 'x' . $count . "\n";
		}
	}

	if ( ! $has_meta_table ) {
		echo "    form meta          : table absent\n";
		continue;
	}

	// -------------------------------------------------------------------
	// THE VERIFIED ACCOUNT-FEED SHAPE, called out on its own before the
	// general meta dump. Every 'user_registration_feeds' row, decoded,
	// with the discriminator printed explicitly.
	// -------------------------------------------------------------------
	// phpcs:ignore WordPress.DB
	$feed_rows = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT value FROM {$meta_table} WHERE form_id = %d AND meta_key = 'user_registration_feeds'",
			(int) $form_id
		),
		ARRAY_A
	);

	echo "    user_registration_feeds rows (VERIFIED shape, list_id decides create vs update):\n";
	if ( empty( $feed_rows ) ) {
		echo "                         none\n";
	} else {
		foreach ( $feed_rows as $i => $feed_row ) {
			$feed = json_decode( (string) $feed_row['value'], true );
			if ( ! is_array( $feed ) ) {
				echo '                         [' . $i . "] UNDECODABLE — treated as 'create' (stricter)\n";
				continue;
			}

			$list_id      = isset( $feed['list_id'] ) ? $feed['list_id'] : '(absent)';
			$enabled      = array_key_exists( 'enabled', $feed ) ? var_export( $feed['enabled'], true ) : '(absent, treated as enabled)'; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			$cond_status  = isset( $feed['conditionals']['status'] ) ? var_export( $feed['conditionals']['status'], true ) : '(none)'; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			$resolves_to  = ( isset( $feed['list_id'] ) && 'user_update' === $feed['list_id'] ) ? 'update' : 'create';

			// Built as one variable before echoing. An earlier revision put a
			// phpcs:ignore comment at the end of the FIRST line of a
			// multi-line concatenation, which is valid PHP but fragile: any
			// layer that reflows or joins those lines swallows the
			// continuation into the comment and truncates the statement. This
			// chunk is pasted between tools often enough for that to matter.
			$line  = '                         [' . $i . '] list_id=' . var_export( $list_id, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			$line .= '  enabled=' . $enabled;
			$line .= '  conditionals.status=' . $cond_status;
			$line .= '  -> resolves to: ' . $resolves_to;
			echo $line . "\n";
			echo "                             (conditionals are NOT evaluated - a conditional feed still counts as active, per the 2.17.0 rule against reading enforcement from request-shaped data)\n";
		}
	}

	// The sticky fallback flags, printed explicitly.
	// phpcs:ignore WordPress.DB
	$has_reg = $wpdb->get_var(
		$wpdb->prepare( "SELECT value FROM {$meta_table} WHERE form_id = %d AND meta_key = '_has_user_registration'", (int) $form_id )
	);
	// phpcs:ignore WordPress.DB
	$has_upd = $wpdb->get_var(
		$wpdb->prepare( "SELECT value FROM {$meta_table} WHERE form_id = %d AND meta_key = '_has_user_update'", (int) $form_id )
	);
	echo '    _has_user_registration (sticky, fallback only) : ' . ( null === $has_reg ? '(absent)' : var_export( $has_reg, true ) ) . "\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
	echo '    _has_user_update (sticky, fallback only)        : ' . ( null === $has_upd ? '(absent)' : var_export( $has_upd, true ) ) . "\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions

	if ( empty( $feed_rows ) && ( 'yes' === $has_reg || 'yes' === $has_upd ) ) {
		echo "    *** no feed row could be read, so classification fell back to the\n";
		echo "        sticky flags above. If a feed was later deleted, these flags may\n";
		echo "        still say 'yes' for a form that no longer touches an account. ***\n";
	}

	// Every other meta row, for context.
	$meta_rows = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, value FROM {$meta_table} WHERE form_id = %d AND meta_key != 'user_registration_feeds'", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB

	if ( empty( $meta_rows ) ) {
		echo "    other form meta    : none\n";
		continue;
	}

	echo "    other form meta keys : \n";
	foreach ( $meta_rows as $meta ) {
		$key     = (string) $meta['meta_key'];
		$decoded = json_decode( (string) $meta['value'], true );

		echo '                         ' . str_pad( $key, 34 );

		if ( is_array( $decoded ) ) {
			$inner = array_slice( array_keys( $decoded ), 0, 12 );
			echo '{ ' . implode( ', ', array_map( 'sanitize_key', $inner ) ) . ( count( $decoded ) > 12 ? ', …' : '' ) . ' }';
		} else {
			echo '(scalar, len ' . strlen( (string) $meta['value'] ) . ')';
		}

		echo "\n";
	}
}

echo "\n=== WHAT TO CHECK ===\n";
echo "  1. Every form with a 'user_registration_feeds' row should show a\n";
echo "     non-empty ACCOUNT column in the CLASSIFICATION table. If one shows\n";
echo "     '—' despite having feed rows above, report it.\n";
echo "  2. *** THE ONE THAT MATTERS THIS RELEASE: any form whose ONLY active\n";
echo "     feed has list_id = 'user_update' must classify ACCOUNT = update,\n";
echo "     never 'create'. A profile-edit form showing ACCOUNT = create\n";
echo "     becomes STRICT and rejects a signed-in visitor on a missing token —\n";
echo "     this is the Phase 48 failure, reproduced. If you see it, this is a\n";
echo "     regression and must be reported immediately; do not enable the\n";
echo "     provider until it is fixed. ***\n";
echo "  3. A form with BOTH an active registration feed and an active update\n";
echo "     feed should classify 'create' when this chunk is run logged OUT and\n";
echo "     'update' when run logged IN — see the note at the top of this\n";
echo "     report. If it does not change, the login-state tie-break has not\n";
echo "     taken effect.\n";
echo "  4. Any form showing PAY = yes that takes no money is safe but noisy;\n";
echo "     any form showing PAY = '—' that DOES take money is a hole. Report\n";
echo "     either.\n";

echo "\nReport the whole block above verbatim.\n";
