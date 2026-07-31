<?php
/**
 * Fluent Forms replacement verification — chunk 25: payment lifecycle (v2.23.2)
 *
 * The one question in this suite that can cost a real customer real money,
 * plus the regression guard for a hook argument-order bug this release fixed.
 *
 * -------------------------------------------------------------------------
 * PART A — PAYMENT STATUS HOOK SIGNATURE (2.23.2 fix, safe to run anywhere)
 *
 * VERIFIED against BaseProcessor::changeSubmissionPaymentStatus() in both
 * Fluent Forms and Fluent Forms Pro: fluentform/after_payment_status_change
 * fires with TWO arguments, status FIRST —
 * do_action('fluentform/after_payment_status_change', $newStatus,
 * $this->getSubmission()). A prior version of this provider registered its
 * callback with FIVE arguments in Gravity-Forms order ($submission,
 * $transaction, $form_id, $old_status, $new_status), so $submission
 * silently received the status STRING and $new_status was always '' — the
 * 'paid'/'refunded' branches inside on_payment_status_change() could never
 * match anything, and Transaction Defense annotation had never once fired.
 * Nothing crashed, so nothing announced this — it required reading the
 * argument order registered by the hook against the argument order Fluent
 * Forms actually passes.
 *
 * -------------------------------------------------------------------------
 * PART B — CHARGE TIMING
 *
 * If Fluent Forms authorises the card in the BROWSER before the submission
 * reaches the server, then a server-side rejection stops the order but leaves
 * the authorisation standing on the customer's card. They are declined, and
 * they are still holding a pending charge.
 *
 * VERIFIED against every payment gateway shipped in Fluent Forms and Fluent
 * Forms Pro 6.2.7 (2.23.2): none authorises before this plugin's validation
 * runs. Server-side, every gateway charges from
 * fluentform/process_payment_{method}, dispatched on
 * fluentform/before_insert_payment_form — which fires AFTER
 * SubmissionHandlerService::handleValidation(). Client-side, Stripe Inline
 * and Square Inline only tokenise (Square's follow-on verifyBuyer() is a
 * 3-D Secure CHALLENGE, not a charge or a hold); Authorize.Net's card modal,
 * and Paddle/Paystack/RazorPay's equivalents, cannot open until the
 * submission is already accepted (their JS config carries a submission_id);
 * PayPal Inline's button submits our form FIRST and explicitly REJECTS its
 * own order-creation promise when validation fails, so a rejection means no
 * PayPal order is ever created.
 *
 * GSWP_Provider_Fluent_Forms::may_block_payment() therefore now defaults to
 * TRUE — high-risk payments are blocked, not merely scored, when
 * gswp_txn_block is on. This is a source-level verification, not an
 * observation of a real decline. Part B below is how an operator on THIS
 * site's actual gateway confirms it before trusting it on a live payment
 * form — it is a CONFIRMATION step now, not a permission step: blocking is
 * already on unless gswp_ff_txn_block_allowed is filtered to false.
 * -------------------------------------------------------------------------
 *
 * Part A is read-only. Part B's automated section is read-only; its manual
 * section makes one real (test-mode) submission if you choose to run it.
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
// PART A — hook signature regression guard.
// ---------------------------------------------------------------------------
echo "=== A. PAYMENT STATUS HOOK SIGNATURE (2.23.2 regression guard) ===\n\n";

$hook_name = 'fluentform/after_payment_status_change';
$found_cb  = null;

if ( isset( $GLOBALS['wp_filter'][ $hook_name ] ) ) {
	$filter = $GLOBALS['wp_filter'][ $hook_name ];
	foreach ( $filter->callbacks as $priority => $callbacks ) {
		foreach ( $callbacks as $cb ) {
			$fn = $cb['function'];
			if ( is_array( $fn ) && $fn[0] instanceof GSWP_Provider_Fluent_Forms ) {
				$found_cb = $cb;
			}
		}
	}
}

if ( ! GSWP_Form_Provider_Registry::is_on( 'fluent-forms' ) ) {
	echo "  Provider is OFF, so register_hooks() has not run and this hook is not\n";
	echo "  yet attached. Turn the provider on and re-run this chunk to exercise\n";
	echo "  this check — until then it cannot fail OR pass meaningfully.\n\n";
} elseif ( null === $found_cb ) {
	echo "  FAIL: the provider is ON but no callback for {$hook_name} was found.\n";
	echo "  Transaction Defense annotation cannot fire at all. Report this.\n\n";
} else {
	$accepted = (int) $found_cb['accepted_args'];
	printf( "  Registered accepted_args : %d\n", $accepted );
	echo '  ' . ( 2 === $accepted
		? "PASS — matches Fluent Forms' real signature (\$newStatus, \$submission).\n"
		: "FAIL — expected 2. A value of 5 is the pre-2.23.2 bug: \$submission\n         silently received the status STRING and annotation never fired.\n" );

	$reflect_fn = new ReflectionMethod( $provider, 'on_payment_status_change' );
	$params     = $reflect_fn->getParameters();

	echo "\n  Method parameters, in order:\n";
	foreach ( $params as $i => $param ) {
		printf( "    %d. \$%s\n", $i + 1, $param->getName() );
	}

	$first_is_status = isset( $params[0] ) && false !== stripos( $params[0]->getName(), 'status' );
	echo "\n  " . ( $first_is_status
		? "PASS — first parameter is the status.\n"
		: "FAIL — first parameter does not look like a status. Report this method's\n         signature verbatim.\n" );
}

// ---------------------------------------------------------------------------
// PART B — is any of this relevant on this site?
// ---------------------------------------------------------------------------
$payment_forms = array();
foreach ( $provider->forms() as $form_id => $title ) {
	if ( $provider->form_has_payment( $form_id ) ) {
		$payment_forms[ $form_id ] = $title;
	}
}

echo "\n=== B. PAYMENT FORMS ===\n\n";
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
printf( "  %-40s %s\n", 'High-risk blocking (global switch)', '1' === get_option( 'gswp_txn_block', '0' ) ? 'yes' : 'no' );
printf( "  %-40s %s\n", 'Risk threshold', get_option( 'gswp_threshold_txn', '0.8' ) );
printf(
	"  %-40s %s\n",
	'Blocking allowed on Fluent Forms',
	apply_filters( 'gswp_ff_txn_block_allowed', true )
		? 'YES (2.23.2 default — source-verified across every shipped gateway)'
		: 'no (filtered OFF on this site — see gswp_ff_txn_block_allowed)'
);

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
// Lifecycle hook surface, with accepted_args now shown per callback.
// ---------------------------------------------------------------------------
echo "\n=== LIFECYCLE HOOK SURFACE ===\n\n";

$hooks = array(
	'fluentform/after_payment_status_change' => 'used by the provider (both directions) — see Part A for accepted_args',
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
	echo "  (currency and total live here; the provider reads currency from\n";
	echo "   form/global payment settings instead, because this table's row is\n";
	echo "   written only once a payment is TAKEN — after validation, when the\n";
	echo "   currency is actually needed. See form_currency() in the provider.)\n";
}

// ---------------------------------------------------------------------------
// The manual step. Nothing automated can answer this.
// ---------------------------------------------------------------------------
echo "\n=== THE CHARGE-TIMING CONFIRMATION TEST (manual) ===\n\n";
echo "  Blocking is ON BY DEFAULT as of 2.23.2 (see the CONFIGURATION section\n";
echo "  above) for every gateway examined in Fluent Forms and Fluent Forms\n";
echo "  Pro 6.2.7. This test is how you CONFIRM that on your own gateway\n";
echo "  before fully trusting it on a live payment form — not how you decide\n";
echo "  whether to turn blocking on.\n\n";
echo "  On STAGING, with the gateway in TEST MODE:\n\n";
echo "  1. With gswp_txn_block on, force a rejection on a payment form. The\n";
echo "     simplest reliable way is to make the token fail: block\n";
echo "     www.google.com/recaptcha in the browser's network tab and submit.\n";
echo "     The form should be REJECTED (payment forms are strict).\n\n";
echo "  2. Then open the gateway dashboard (Stripe: Payments -> All, including\n";
echo "     incomplete; PayPal: Activity; Square: Payments) and look for an\n";
echo "     authorisation, hold, or incomplete payment intent created at that\n";
echo "     moment.\n\n";
echo "  3. Report which of these you see:\n\n";
echo "     (a) NOTHING in the gateway -> matches the 2.23.2 source finding.\n";
echo "         Blocking is correctly on and safe. No action needed.\n\n";
echo "     (b) An authorisation / incomplete intent -> the card was authorised\n";
echo "         in the browser before this plugin's validation ran, which\n";
echo "         contradicts the source verification for this gateway. Turn\n";
echo "         blocking back OFF for this site immediately:\n";
echo "             add_filter( 'gswp_ff_txn_block_allowed', '__return_false' );\n";
echo "         and report which gateway produced this result — the source\n";
echo "         finding needs re-checking against whatever add-on or\n";
echo "         customisation this site is running.\n\n";
echo "  Repeat for every gateway configured on the site — the answer is a\n";
echo "  property of the gateway integration, not of Fluent Forms as a whole.\n";

echo "\nReport the whole block above verbatim, including the gateway result.\n";
