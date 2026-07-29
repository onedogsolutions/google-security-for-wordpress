<?php
/**
 * Fluent Forms replacement verification — chunk 25: payment lifecycle (v2.23.0)
 *
 * The one question in this suite that can cost a real customer real money.
 *
 * -------------------------------------------------------------------------
 * CHARGE TIMING
 *
 * If Fluent Forms authorises the card in the BROWSER before the submission
 * reaches the server, then a server-side rejection stops the order but leaves
 * the authorisation standing on the customer's card. They are declined, and
 * they are still holding a pending charge.
 *
 * This is the 2.16.0 Stripe question. It is being asked once, in advance,
 * rather than discovered in production a second time.
 *
 * Until it is answered on a live install, GSWP_Provider_Fluent_Forms does NOT
 * block high-risk payments even when gswp_txn_block is on. It scores them,
 * logs the score, and annotates the outcome — everything except the one action
 * that could strand a hold on somebody's card. Blocking is enabled per site
 * with the gswp_ff_txn_block_allowed filter, once this chunk says it is safe.
 * -------------------------------------------------------------------------
 *
 * Read-only. Makes no payment and calls no gateway.
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

// ---------------------------------------------------------------------------
// Is any of this relevant on this site?
// ---------------------------------------------------------------------------
$payment_forms = array();
foreach ( $provider->forms() as $form_id => $title ) {
	if ( $provider->form_has_payment( $form_id ) ) {
		$payment_forms[ $form_id ] = $title;
	}
}

echo "=== PAYMENT FORMS ===\n\n";
if ( empty( $payment_forms ) ) {
	echo "  None. Transaction Defense has nothing to act on here, and the charge\n";
	echo "  timing question below does not arise on this site. Chunks 20-24 are\n";
	echo "  sufficient.\n\n";
} else {
	foreach ( $payment_forms as $form_id => $title ) {
		echo '  #' . $form_id . '  ' . $title . "\n";
	}
	echo "\n";
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------
echo "=== TRANSACTION DEFENSE CONFIGURATION ===\n\n";

$enterprise = 'enterprise' === get_option( 'gswp_key_type', 'classic' );

printf( "  %-40s %s\n", 'Key type', get_option( 'gswp_key_type', 'classic' ) );
printf( "  %-40s %s\n", 'Transaction Defense enabled', '1' === get_option( 'gswp_txn_defense', '0' ) ? 'yes' : 'no' );
printf( "  %-40s %s\n", 'High-risk blocking (global)', '1' === get_option( 'gswp_txn_block', '0' ) ? 'yes' : 'no' );
printf( "  %-40s %s\n", 'Risk threshold', get_option( 'gswp_threshold_txn', '0.8' ) );
printf( "  %-40s %s\n", 'Blocking allowed on Fluent Forms', apply_filters( 'gswp_ff_txn_block_allowed', false ) ? 'YES (filter overridden)' : 'no (default — see below)' );

if ( ! $enterprise ) {
	echo "\n  Not an Enterprise key, so no transactionData is ever sent and the\n";
	echo "  charge-timing question is moot until that changes.\n";
}

// ---------------------------------------------------------------------------
// What the provider can actually build for an assessment.
// ---------------------------------------------------------------------------
if ( ! empty( $payment_forms ) ) {
	echo "\n=== BILLING FIELD MAPPING (per payment form) ===\n\n";
	echo "  Google requires billing region code AND postal code before it will\n";
	echo "  accept transactionData. Below its documented minimum the provider\n";
	echo "  sends nothing and degrades to a plain score, which is safe but means\n";
	echo "  no fraud signal. A form showing 'no' below gets score-only.\n\n";

	$forms_table = $wpdb->prefix . 'fluentform_forms';

	printf( "  %-5s %-28s %-30s %s\n", 'ID', 'TITLE', 'ADDRESS/EMAIL/NAME FIELDS', 'CAN SEND TXN DATA' );
	echo '  ' . str_repeat( '-', 96 ) . "\n";

	foreach ( $payment_forms as $form_id => $title ) {
		$json     = $wpdb->get_var( $wpdb->prepare( "SELECT form_fields FROM {$forms_table} WHERE id = %d", (int) $form_id ) ); // phpcs:ignore WordPress.DB
		$relevant = array();

		foreach ( array( 'address', 'input_email', 'input_name' ) as $needle ) {
			if ( is_string( $json ) && false !== stripos( $json, '"' . $needle . '"' ) ) {
				$relevant[] = $needle;
			}
		}

		printf(
			"  %-5s %-28s %-30s %s\n",
			$form_id,
			substr( (string) $title, 0, 27 ),
			empty( $relevant ) ? '—' : implode( ', ', $relevant ),
			in_array( 'address', $relevant, true ) ? 'maybe (needs country+postcode)' : 'no — score only'
		);
	}
}

// ---------------------------------------------------------------------------
// Lifecycle hook surface.
// ---------------------------------------------------------------------------
echo "\n=== LIFECYCLE HOOK SURFACE ===\n\n";

$hooks = array(
	'fluentform/after_payment_status_change' => 'used by the provider (both directions)',
	'fluentform/payment_refunded'            => 'not used — would double-annotate',
	'fluentform/submission_inserted'         => 'used to persist the assessment name',
);

foreach ( $hooks as $hook => $note ) {
	$count = isset( $GLOBALS['wp_filter'][ $hook ] ) ? count( $GLOBALS['wp_filter'][ $hook ]->callbacks ) : 0;
	printf( "  %-42s %-10s %s\n", $hook, $count > 0 ? 'hooked' : 'nobody', $note );
}

echo "\n  'nobody' on the first two is expected while the provider is switched\n";
echo "  off — it registers no hooks until then. Re-run after enabling it.\n";

$txn_table = $wpdb->prefix . 'fluentform_transactions';
$has_txn   = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $txn_table ) ) === $txn_table; // phpcs:ignore WordPress.DB

if ( $has_txn ) {
	$columns = $wpdb->get_col( "SHOW COLUMNS FROM {$txn_table}" ); // phpcs:ignore WordPress.DB
	echo "\n  fluentform_transactions columns:\n    " . implode( ', ', (array) $columns ) . "\n";
	echo "  (currency and total live here; the provider currently reads currency\n";
	echo "   from form meta, which is the unverified path. If a 'currency' column\n";
	echo "   is listed above, that is the better binding — report it.)\n";
}

// ---------------------------------------------------------------------------
// The manual step. Nothing automated can answer this.
// ---------------------------------------------------------------------------
echo "\n=== THE CHARGE-TIMING TEST (manual, and the point of this chunk) ===\n\n";
echo "  On STAGING, with the gateway in TEST MODE:\n\n";
echo "  1. Enable the provider and set gswp_txn_block on, then force a rejection\n";
echo "     on a payment form. The simplest reliable way is to make the token\n";
echo "     fail: block www.google.com/recaptcha in the browser's network tab and\n";
echo "     submit. The form should be REJECTED (payment forms are strict).\n\n";
echo "  2. Then open the gateway dashboard (Stripe: Payments -> All, including\n";
echo "     incomplete; PayPal: Activity) and look for an authorisation, hold, or\n";
echo "     incomplete payment intent created at that moment.\n\n";
echo "  3. Report which of these you see:\n\n";
echo "     (a) NOTHING in the gateway  -> the card is charged server-side, after\n";
echo "         our validation. Blocking is safe. Enable it with:\n";
echo "             add_filter( 'gswp_ff_txn_block_allowed', '__return_true' );\n\n";
echo "     (b) An authorisation / incomplete intent -> the card is authorised in\n";
echo "         the browser BEFORE we ever see the submission. Blocking would\n";
echo "         strand a hold on a real customer's card. LEAVE IT OFF. Scoring,\n";
echo "         logging and annotation all still work and are still worth having.\n\n";
echo "  Repeat for every gateway configured on the site — the answer is a\n";
echo "  property of the gateway integration, not of Fluent Forms.\n";

echo "\nReport the whole block above verbatim, including the gateway result.\n";
