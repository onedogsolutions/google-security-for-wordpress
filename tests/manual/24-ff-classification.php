<?php
/**
 * Fluent Forms replacement verification — chunk 24: classification (v2.23.0)
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
 * The account binding is the unverified one. Fluent Forms Pro stores
 * integration feeds as rows in fluentform_form_meta, and neither the meta_key
 * naming nor the key distinguishing "create a user" from "update a user" is
 * confirmed. Getting it wrong is not cosmetic: a profile-edit form mistaken for
 * a signup is scored under the stricter threshold and rejected outright when
 * its token is missing — which in 2.22.0, on Gravity Forms, is exactly how a
 * real customer came to be told she was spam.
 *
 * So this chunk prints EVERY meta_key for every form verbatim. That is the
 * evidence; the classification is only the reading.
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
echo '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ) . "\n\n";

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

// ---------------------------------------------------------------------------
// The evidence: has_payment, field elements, and every meta row.
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

	// Field elements, in order, deduplicated with counts. This is what the
	// payment and password fallbacks scan.
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

	// Every meta row. THE account binding evidence.
	if ( ! $has_meta_table ) {
		echo "    form meta          : table absent\n";
		continue;
	}

	$meta_rows = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, value FROM {$meta_table} WHERE form_id = %d", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB

	if ( empty( $meta_rows ) ) {
		echo "    form meta          : none\n";
		continue;
	}

	echo "    form meta keys     : \n";
	foreach ( $meta_rows as $meta ) {
		$key     = (string) $meta['meta_key'];
		$decoded = json_decode( (string) $meta['value'], true );

		echo '                         ' . str_pad( $key, 34 );

		if ( is_array( $decoded ) ) {
			// Inner keys only — the values are the site's configuration and may
			// contain credentials for third-party integrations.
			$inner = array_slice( array_keys( $decoded ), 0, 12 );
			echo '{ ' . implode( ', ', array_map( 'sanitize_key', $inner ) ) . ( count( $decoded ) > 12 ? ', …' : '' ) . ' }';

			// The two keys that decide create-vs-update, printed verbatim.
			foreach ( array( 'feedType', 'feed_type', 'userRegistrationType', 'type', 'enabled' ) as $probe ) {
				if ( isset( $decoded[ $probe ] ) && is_scalar( $decoded[ $probe ] ) ) {
					echo "\n                         " . str_repeat( ' ', 34 ) . '  ' . $probe . ' = ' . var_export( $decoded[ $probe ], true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
				}
			}
		} else {
			echo '(not JSON, len ' . strlen( (string) $meta['value'] ) . ')';
		}

		echo "\n";
	}
}

echo "\n=== WHAT TO CHECK ===\n";
echo "  1. Every form with a User Registration or User Update integration should\n";
echo "     show a non-empty ACCOUNT column. If one shows '—', the meta_key does\n";
echo "     not contain 'user_registration' or 'user_update' on this version and\n";
echo "     the binding needs correcting — report the meta key verbatim.\n";
echo "  2. A profile-edit form showing ACCOUNT = create is the dangerous\n";
echo "     misreading: it becomes STRICT and rejects on a missing token. Correct\n";
echo "     it immediately with the gswp_ff_account_feed_type filter and report\n";
echo "     the meta keys so it can be fixed properly.\n";
echo "  3. Any form showing PAY = yes that takes no money is safe but noisy; any\n";
echo "     form showing PAY = '—' that DOES take money is a hole. Report either.\n";

echo "\nReport the whole block above verbatim.\n";
