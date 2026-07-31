<?php
/**
 * Fluent Forms replacement verification — chunk 27: payment authorisation (v2.23.2)
 *
 * THE ONE THAT CAN COST A CUSTOMER MONEY. Chunk 25 explains why blocking is
 * on by default in 2.23.2 (no gateway Fluent Forms or Fluent Forms Pro 6.2.7
 * ships authorises a card before this plugin's validation runs). That is a
 * SOURCE READ. This chunk is how it becomes an OBSERVATION on the gateway a
 * particular site actually uses.
 *
 * -------------------------------------------------------------------------
 * WHY THIS CHUNK EXISTS SEPARATELY FROM 25
 *
 * The first attempt at this test on the reporting site did not run, and
 * neither the operator nor the report noticed at the time. The method was
 * "block www.google.com/recaptcha in the browser's network tab, the form
 * should be REJECTED" — and it was not rejected. Blocking the challenge
 * bundle (recaptcha__en.js) does not stop reCAPTCHA Enterprise minting a
 * score-only token: enterprise.js had already loaded and answered. The
 * submission was scored, passed, and the gateway charged the card, exactly
 * as a healthy submission should. The gateway then showed a successful
 * payment, which reads like the alarming result (b) — an authorisation that
 * survived a rejection — when in fact no rejection had ever been attempted.
 *
 * It was compounded by the diagnostic: the mu-plugin snippet reported the
 * token with isset(), which is TRUE for an empty string, so a field that was
 * present but unfilled and a field carrying a real token both printed the
 * same word. Chunk 22 now prints three states.
 *
 * The lesson is the reason this file exists: **a test whose premise silently
 * fails to hold reports the outcome of a different experiment, and reports it
 * with the same confidence.** So this chunk does not ask the operator to
 * disrupt the browser and hope. It (1) proves from stored evidence whether a
 * rejection actually happened, and (2) gives a way to force one that cannot
 * quietly not-happen.
 * -------------------------------------------------------------------------
 *
 * Read-only. Writes nothing, calls no gateway, creates no submission.
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

$payment_forms = array();
foreach ( $provider->forms() as $form_id => $title ) {
	if ( $provider->form_has_payment( $form_id ) ) {
		$payment_forms[ $form_id ] = $title;
	}
}

echo "  SCOPE: this chunk covers PAYMENT forms only. An account form (User\n";
echo "  Registration / User Update) is not shown here at all, whatever it does\n";
echo "  — chunk 24 is the one that classifies those and dumps their feed rows.\n";
echo "  Running this chunk after creating an account form will report on the\n";
echo "  payment forms and say nothing about the new one.\n\n";

printf( "  Payment forms on this site: %d of %d total\n\n", count( $payment_forms ), count( $provider->forms() ) );

if ( empty( $payment_forms ) ) {
	echo "No Fluent Forms form takes payment on this site. Nothing to test here;\n";
	echo "if you came looking for an account form, run chunk 24.\n";
	return;
}

// ---------------------------------------------------------------------------
// A. Did this plugin actually reject anything? Stored evidence, not memory.
// ---------------------------------------------------------------------------
echo "=== A. HAS THIS PLUGIN EVER REJECTED A SUBMISSION ON A PAYMENT FORM? ===\n\n";
echo "  This is the question the first attempt could not answer. A successful\n";
echo "  charge in the gateway is only evidence about charge TIMING if a\n";
echo "  rejection was genuinely attempted at the same moment.\n\n";

$any_rejection = false;

foreach ( $payment_forms as $form_id => $title ) {
	$rejection = method_exists( $provider, 'last_rejection' ) ? $provider->last_rejection( $form_id ) : null;

	if ( ! is_array( $rejection ) || '' === (string) $rejection['reason'] ) {
		printf( "  #%-4s %-30s no rejection ever recorded\n", $form_id, substr( (string) $title, 0, 29 ) );
		continue;
	}

	$any_rejection = true;
	printf(
		"  #%-4s %-30s LAST REJECTION: %s  (%s UTC, %s ago)\n",
		$form_id,
		substr( (string) $title, 0, 29 ),
		$rejection['reason'],
		gmdate( 'Y-m-d H:i:s', (int) $rejection['time'] ),
		human_time_diff( (int) $rejection['time'] )
	);
}

if ( ! $any_rejection ) {
	echo "\n  *** NO PAYMENT FORM HAS EVER BEEN REJECTED BY THIS PLUGIN. ***\n";
	echo "  If you believed you ran the charge-timing test, it did not run: the\n";
	echo "  submission was scored and ADMITTED, and any resulting charge is a\n";
	echo "  healthy payment, not an authorisation that outlived a rejection.\n";
	echo "  Use section C below to force one that cannot silently not-happen.\n";
}

// ---------------------------------------------------------------------------
// B. What the recent submissions on payment forms actually record.
// ---------------------------------------------------------------------------
echo "\n=== B. RECENT PAYMENT-FORM SUBMISSIONS AND WHAT WE RECORDED ON THEM ===\n\n";
echo "  gswp_assessment_name present  => we reached Google, so the token was\n";
echo "                                   real and non-empty on that submission.\n";
echo "  gswp_unverified present       => admitted WITHOUT a verified token\n";
echo "                                   (fail-open); the score is not ours.\n";
echo "  Neither                       => scored before 2.23.x, or the provider\n";
echo "                                   was off when it was submitted.\n\n";

$subs_table = $wpdb->prefix . 'fluentform_submissions';
$meta_table = $wpdb->prefix . 'fluentform_submission_meta';
$txn_table  = $wpdb->prefix . 'fluentform_transactions';

$has_txn = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $txn_table ) ) === $txn_table; // phpcs:ignore WordPress.DB

$ids = implode( ',', array_map( 'intval', array_keys( $payment_forms ) ) );

$subs = $wpdb->get_results( // phpcs:ignore WordPress.DB
	"SELECT id, form_id, payment_status, created_at
	 FROM {$subs_table}
	 WHERE form_id IN ({$ids})
	 ORDER BY id DESC
	 LIMIT 15",
	ARRAY_A
);

if ( empty( $subs ) ) {
	echo "  No submissions on any payment form yet.\n";
} else {
	printf( "  %-7s %-6s %-14s %-21s %-26s %s\n", 'SUB ID', 'FORM', 'PAY STATUS', 'CREATED', 'GSWP ASSESSMENT', 'FLAGS' );
	echo '  ' . str_repeat( '-', 104 ) . "\n";

	foreach ( $subs as $sub ) {
		$assessment = $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT value FROM {$meta_table} WHERE response_id = %d AND meta_key = 'gswp_assessment_name'", (int) $sub['id'] )
		);
		$unverified = $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT value FROM {$meta_table} WHERE response_id = %d AND meta_key = 'gswp_unverified'", (int) $sub['id'] )
		);
		$annotated  = $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT value FROM {$meta_table} WHERE response_id = %d AND meta_key = 'gswp_annotated'", (int) $sub['id'] )
		);

		$flags = array();
		if ( $unverified ) {
			$flags[] = 'UNVERIFIED';
		}
		if ( $annotated ) {
			$flags[] = 'annotated=' . $annotated;
		}

		printf(
			"  %-7s %-6s %-14s %-21s %-26s %s\n",
			$sub['id'],
			$sub['form_id'],
			(string) $sub['payment_status'],
			(string) $sub['created_at'],
			$assessment ? substr( (string) $assessment, -24 ) : '(none)',
			empty( $flags ) ? '--' : implode( ',', $flags )
		);
	}

	echo "\n  A row WITH an assessment name and a paid status is the happy path\n";
	echo "  fully exercised: token injected, filled, delivered, scored, admitted,\n";
	echo "  charged. That is worth confirming in its own right — but it is NOT\n";
	echo "  the charge-timing test.\n";
}

if ( $has_txn ) {
	$txns = $wpdb->get_results( // phpcs:ignore WordPress.DB
		"SELECT id, submission_id, form_id, payment_total, currency, status, payment_method, charge_id, created_at
		 FROM {$txn_table}
		 WHERE form_id IN ({$ids})
		 ORDER BY id DESC
		 LIMIT 15",
		ARRAY_A
	);

	echo "\n  --- fluentform_transactions (a row here means money moved) ---\n\n";

	if ( empty( $txns ) ) {
		echo "    none\n";
	} else {
		printf( "    %-5s %-8s %-6s %-10s %-10s %-14s %-21s %s\n", 'ID', 'SUB', 'FORM', 'TOTAL', 'STATUS', 'METHOD', 'CREATED', 'CHARGE ID' );
		echo '    ' . str_repeat( '-', 104 ) . "\n";
		foreach ( $txns as $txn ) {
			printf(
				"    %-5s %-8s %-6s %-10s %-10s %-14s %-21s %s\n",
				$txn['id'],
				(string) $txn['submission_id'],
				(string) $txn['form_id'],
				(string) $txn['payment_total'] . ' ' . (string) $txn['currency'],
				(string) $txn['status'],
				(string) $txn['payment_method'],
				(string) $txn['created_at'],
				substr( (string) $txn['charge_id'], 0, 30 )
			);
		}
		echo "\n    Cross-reference these against the gateway dashboard. Every charge\n";
		echo "    in the gateway SHOULD have a row here. A charge in the gateway\n";
		echo "    with NO row here is the finding that matters: money moved for a\n";
		echo "    submission Fluent Forms never completed.\n";
	}
}

// ---------------------------------------------------------------------------
// C. How to force a rejection that cannot silently not-happen.
// ---------------------------------------------------------------------------
echo "\n=== C. FORCING A REAL REJECTION (pick ONE, then check the gateway) ===\n\n";
echo "  Do NOT use \"block www.google.com/recaptcha in devtools\". Blocking the\n";
echo "  challenge bundle does not stop Enterprise minting a score-only token,\n";
echo "  so the submission is scored and admitted and nothing is tested.\n\n";

echo "  METHOD 1 — remove the field from the DOM (most faithful; simulates a\n";
echo "  visitor whose token never arrived). On the form page, in the DevTools\n";
echo "  console, immediately before clicking submit:\n\n";
echo "      document.querySelector('input[name=\"gswp_ff_token\"]').remove();\n\n";
echo "  Removing beats blanking: the footer bootstrap refills a field that is\n";
echo "  still in the DOM (tokens are replaced in place and never cleared —\n";
echo "  the 2.22.1 invariant), so a blanked field can silently repopulate\n";
echo "  before you submit. A removed field cannot come back.\n\n";

echo "  METHOD 2 — make the score impossible to pass (exercises the reject\n";
echo "  path AFTER a real assessment, which is closer to a live decline).\n";
echo "  This form scores against the option below; set it above 1.0, submit,\n";
echo "  then set it back:\n\n";

foreach ( $payment_forms as $form_id => $title ) {
	$policy  = method_exists( $provider, 'form_policy' ) ? $provider->form_policy( $form_id ) : array();
	$context = isset( $policy['context'] ) ? $policy['context'] : 'checkout';
	$option  = 'gswp_threshold_' . $context;

	printf( "      form #%-3s  %-26s  %s  (currently %s)\n", $form_id, substr( (string) $title, 0, 25 ), $option, get_option( $option, '0.5' ) );
}

echo "\n      wp option update gswp_threshold_checkout 1.1     # reject everything\n";
echo "      ...submit the form in a browser...\n";
echo "      wp option update gswp_threshold_checkout 0.5     # put it back\n\n";
echo "  NOTE: on a site without WooCommerce that option has no dial on the\n";
echo "  settings screen — payment forms share the checkout context with\n";
echo "  WooCommerce in BOTH providers, and that panel only renders when\n";
echo "  WooCommerce is active. WP-CLI or the database is the only way to\n";
echo "  reach it here.\n\n";

echo "  THEN, whichever method you used:\n\n";
echo "  1. Confirm the form was actually refused — a message on screen, and\n";
echo "     re-run THIS CHUNK: section A must now show a LAST REJECTION for\n";
echo "     that form, timestamped to the moment you submitted. If section A\n";
echo "     still says 'no rejection ever recorded', the rejection did not\n";
echo "     happen and anything you see in the gateway is unrelated. Stop and\n";
echo "     report that rather than reading the gateway.\n\n";
echo "  2. ONLY THEN open the gateway dashboard (Stripe: Payments -> All,\n";
echo "     including incomplete and uncaptured; PayPal: Activity; Square:\n";
echo "     Payments) and look at that exact minute.\n\n";
echo "  3. Report which you see:\n\n";
echo "     (a) NO new charge, hold, authorisation or incomplete intent ->\n";
echo "         matches the 2.23.2 source finding. Blocking is safe on this\n";
echo "         gateway. A PaymentMethod object with no PaymentIntent is\n";
echo "         expected and is NOT a hold — Stripe and Square both tokenise\n";
echo "         in the browser, which moves no money.\n\n";
echo "     (b) A hold / authorisation / uncaptured or incomplete intent ->\n";
echo "         the card was authorised before this plugin's validation ran,\n";
echo "         contradicting the source read for this gateway. Turn blocking\n";
echo "         off for this site immediately:\n";
echo "             add_filter( 'gswp_ff_txn_block_allowed', '__return_false' );\n";
echo "         and report the gateway and the intent status.\n\n";
echo "  Repeat per gateway. The answer is a property of the gateway\n";
echo "  integration, not of Fluent Forms as a whole.\n";

echo "\nReport the whole block above verbatim.\n";
