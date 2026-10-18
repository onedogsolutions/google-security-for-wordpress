<?php
// GSWP manual test 34 — Gravity Forms low-score policy and the GF Stripe
// Payment Element pre-check, exercised through the REAL verifier and the REAL
// Gravity Forms submission pipeline, with only Google's HTTP response stubbed.
//
// Run with: wp eval-file tests/manual/34-gf-low-score-and-stripe-precheck.php
// or paste into an MCP PHP-execution tool. Self-cleaning: it creates two
// throwaway forms (and a Stripe feed on one), runs every scenario, then deletes
// them and restores the options it touched. Nothing reaches Google or Stripe.
//
// Written for v2.31.0; §7b added in v2.31.1. Two field reports from one live site:
//
//  1. A volunteer applicant was refused "did not pass our automated security
//     check" on every attempt. That is a low score, which a refresh cannot
//     change. On a form that takes no payment and creates no account the
//     submission is now admitted and filed in Gravity Forms' Spam folder.
//
//  2. Gravity Forms Stripe payments failed. Two defects: the Payment Element
//     validates in an admin-ajax pre-check and again on completion, re-scoring
//     a spent token (DUPE); and transactionData was never built for a Stripe
//     form because the feed keys read were wrong — so a low score refused a
//     payment that Transaction defense would have cleared.
//
// Per the Phase 57 lesson: assert on what crosses the wire — the assessment
// request body actually sent, the number of calls made, the entry status GF
// actually stored — not on the presence of the code meant to produce them.

$t    = function ( $label, $ok, $d = '' ) {
	printf( "%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $label, '' !== $d ? " [{$d}]" : '' );
};
$fail = 0;
$chk  = function ( $label, $ok, $d = '' ) use ( $t, &$fail ) {
	$t( $label, $ok, $d );
	if ( ! $ok ) {
		$fail++;
	}
};

// --- Preflight ---------------------------------------------------------------
if ( ! class_exists( 'GFAPI' ) ) {
	echo "SKIP: Gravity Forms is not active.\n";
	return;
}
if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) || ! GSWP_Recaptcha_Loader::will_load() ) {
	echo "SKIP: needs an Enterprise key configured (the assessment path is what is exercised).\n";
	return;
}

$saved = array();
foreach ( array( 'gswp_txn_defense', 'gswp_txn_block', 'gswp_threshold_gf_submit', 'gswp_threshold_checkout', 'gswp_threshold_txn', GSWP_Provider_Gravity_Forms::INJECTION_OPTION, GSWP_Provider_Gravity_Forms::REJECTION_OPTION ) as $opt ) {
	$saved[ $opt ] = get_option( $opt, null );
}
update_option( 'gswp_txn_defense', '1' );
update_option( 'gswp_txn_block', '0' );
update_option( 'gswp_threshold_gf_submit', '0.5' );
update_option( 'gswp_threshold_checkout', '0.5' );
update_option( 'gswp_threshold_txn', '0.8' );

// --- Google stub -------------------------------------------------------------
// Each scenario sets $stub['next'] (score, valid, reason, risk). Every request
// body sent to the assessments endpoint is captured, so assertions are on the
// payload this plugin actually built.
$stub = array(
	'next'   => array(),
	'calls'  => 0,
	'bodies' => array(),
);
$http = function ( $pre, $args, $url ) use ( &$stub ) {
	if ( false === strpos( (string) $url, 'recaptchaenterprise.googleapis.com' ) ) {
		return $pre;
	}
	$stub['calls']++;
	$body             = json_decode( (string) $args['body'], true );
	$stub['bodies'][] = $body;
	$n                = $stub['next'];
	$resp             = array(
		'name'           => 'projects/test/assessments/t34-' . $stub['calls'],
		'tokenProperties' => array(
			'valid'  => ! isset( $n['valid'] ) || $n['valid'],
			'action' => isset( $body['event']['expectedAction'] ) ? $body['event']['expectedAction'] : '',
		),
		'riskAnalysis'   => array( 'score' => isset( $n['score'] ) ? $n['score'] : 0.9 ),
	);
	if ( isset( $n['valid'] ) && ! $n['valid'] ) {
		$resp['tokenProperties']['invalidReason'] = isset( $n['reason'] ) ? $n['reason'] : 'DUPE';
	}
	if ( isset( $n['risk'] ) ) {
		$resp['fraudPreventionAssessment'] = array( 'transactionRisk' => $n['risk'] );
	}
	return array(
		'headers'  => array(),
		'body'     => wp_json_encode( $resp ),
		'response' => array( 'code' => 200, 'message' => 'OK' ),
		'cookies'  => array(),
	);
};
add_filter( 'pre_http_request', $http, 10, 3 );

// Use the live provider when it is switched on (registering a second one would
// score every submission twice); otherwise bring up one of our own, so the run
// does not depend on the site's setting.
$provider = GSWP_Form_Provider_Registry::is_on( 'gravity-forms' ) ? GSWP_Form_Provider_Registry::get( 'gravity-forms' ) : null;
if ( ! $provider ) {
	$provider = new GSWP_Provider_Gravity_Forms();
	$provider->register_hooks( new GSWP_Verifier() );
}
$prop = new ReflectionProperty( $provider, 'pending_assessment' );
$prop->setAccessible( true );

// The verifier caches a token's verdict for the rest of the PHP request, so a
// later scenario reusing a token would be answered from memory. Real requests
// are separate processes; clear it between scenarios to match.
$eprop = new ReflectionProperty( $provider, 'errors' );
$eprop->setAccessible( true );
$err   = function ( $form_id ) use ( $eprop, $provider ) {
	$e = (array) $eprop->getValue( $provider );
	return isset( $e[ $form_id ] ) ? (string) $e[ $form_id ] : '';
};
$vprop = new ReflectionProperty( $provider, 'verifier' );
$vprop->setAccessible( true );
$cache = new ReflectionProperty( 'GSWP_Verifier', 'token_cache' );
$cache->setAccessible( true );

// --- Fixtures ----------------------------------------------------------------
$volunteer_id = GFAPI::add_form(
	array(
		'title'  => 'GSWP t34 Volunteer ' . wp_generate_password( 6, false ),
		'fields' => array(
			array( 'type' => 'text', 'id' => 1, 'label' => 'Name', 'pageNumber' => 1 ),
			array( 'type' => 'email', 'id' => 2, 'label' => 'Email', 'pageNumber' => 1 ),
			array( 'type' => 'page', 'id' => 3, 'label' => 'Page 2', 'pageNumber' => 2 ),
			array( 'type' => 'textarea', 'id' => 4, 'label' => 'Why volunteer?', 'pageNumber' => 2 ),
		),
	)
);
$stripe_id = GFAPI::add_form(
	array(
		'title'  => 'GSWP t34 Stripe ' . wp_generate_password( 6, false ),
		'fields' => array(
			array(
				'type'        => 'product',
				'inputType'   => 'singleproduct',
				'id'          => 1,
				'label'       => 'Donation',
				'basePrice'   => '$5.00',
				'inputs'      => array(
					array( 'id' => '1.1', 'label' => 'Name' ),
					array( 'id' => '1.2', 'label' => 'Price' ),
					array( 'id' => '1.3', 'label' => 'Quantity' ),
				),
			),
			array( 'type' => 'email', 'id' => 2, 'label' => 'Email' ),
			array(
				'type'        => 'address',
				'id'          => 3,
				'label'       => 'Address',
				'addressType' => 'international',
				'inputs'      => array(
					array( 'id' => '3.1', 'label' => 'Street Address' ),
					array( 'id' => '3.2', 'label' => 'Address Line 2' ),
					array( 'id' => '3.3', 'label' => 'City' ),
					array( 'id' => '3.4', 'label' => 'State / Province' ),
					array( 'id' => '3.5', 'label' => 'ZIP / Postal Code' ),
					array( 'id' => '3.6', 'label' => 'Country' ),
				),
			),
			array( 'type' => 'total', 'id' => 4, 'label' => 'Total' ),
		),
	)
);
$t( 'fixtures created', ! is_wp_error( $volunteer_id ) && ! is_wp_error( $stripe_id ), "volunteer #{$volunteer_id}, stripe #{$stripe_id}" );

// A Payment Element product feed: maps customer email only, no address —
// exactly the shape that left Stripe forms with no transactionData before.
GFAPI::add_feed(
	$stripe_id,
	array(
		'feedName'                  => 't34',
		'transactionType'           => 'product',
		'paymentAmount'             => 'form_total',
		'customerInformation_email' => '2',
	),
	'gravityformsstripe'
);

// Both forms count as rendered, so a missing token is not a coverage gap.
$inj                  = (array) get_option( GSWP_Provider_Gravity_Forms::INJECTION_OPTION, array() );
$inj[ $volunteer_id ] = time();
$inj[ $stripe_id ]    = time();
update_option( GSWP_Provider_Gravity_Forms::INJECTION_OPTION, $inj, false );

$policy_v = $provider->form_policy( $volunteer_id );
$policy_s = $provider->form_policy( $stripe_id );
$chk( 'volunteer form is non-strict, action submit', ! $provider->form_is_strict( $volunteer_id ) && 'submit' === $policy_v['action'] );
$chk( 'stripe form is strict, action checkout', $provider->form_is_strict( $stripe_id ) && 'checkout' === $policy_s['action'] );

$volunteer_input = function ( $token ) {
	return array(
		'input_1'       => 'Pat Applicant',
		'input_2'       => 'qa-t34@onedog.solutions',
		'input_4'       => 'I love dogs.',
		'gswp_gf_token' => $token,
	);
};
$stripe_input = array(
	'input_1_1' => 'Donation',
	'input_1_2' => '$5.00',
	'input_1_3' => '1',
	'input_2'   => 'qa-t34-payer@onedog.solutions',
	'input_3_1' => '123 Main St',
	'input_3_3' => 'San Antonio',
	'input_3_4' => 'Texas',
	'input_3_5' => '78201',
	'input_3_6' => 'United States',
);
$reset_post = function () use ( $vprop, $cache, $provider, $eprop ) {
	$_POST = array();
	$eprop->setValue( $provider, array() );
	$cache->setValue( $vprop->getValue( $provider ), array() );
	if ( class_exists( 'GFFormDisplay' ) ) {
		GFFormDisplay::$submission = array();
	}
};
$as_precheck = function ( $on ) {
	remove_all_filters( 'wp_doing_ajax' );
	if ( $on ) {
		add_filter( 'wp_doing_ajax', '__return_true' );
	}
};

// --- 1. Volunteer: low score is filed as spam, not refused --------------------
$reset_post();
$stub['next'] = array( 'score' => 0.3 );
$r            = GFAPI::submit_form( $volunteer_id, $volunteer_input( 'tok-v-low' ), array(), 0, 2 );
$entry        = ! empty( $r['entry_id'] ) ? GFAPI::get_entry( $r['entry_id'] ) : null;
$chk( '1 low score on volunteer form is accepted', ! empty( $r['is_valid'] ), isset( $r['validation_messages'] ) ? wp_json_encode( $r['validation_messages'] ) : '' );
$chk( '1 entry stored with status spam', is_array( $entry ) && 'spam' === $entry['status'], is_array( $entry ) ? $entry['status'] : 'no entry' );
$notes = is_array( $entry ) ? GFAPI::get_notes( array( 'entry_id' => $entry['id'] ) ) : array();
$note  = '';
foreach ( (array) $notes as $n ) {
	$note .= $n->value . ' ';
}
$chk( '1 spam note names the score and threshold', false !== strpos( $note, '0.30' ) && false !== strpos( $note, '0.50' ), trim( $note ) );
$chk( '1 spam reason stored on entry meta', is_array( $entry ) && '' !== (string) gform_get_meta( $entry['id'], GSWP_Provider_Gravity_Forms::META_SPAM_REASON ) );
$last = $provider->last_rejection( $volunteer_id );
$chk( '1 coverage report records the filing', is_array( $last ) && 'low score (filed as spam)' === $last['reason'] );

// --- 2. Volunteer: a passing score is an ordinary entry -----------------------
$reset_post();
$stub['next'] = array( 'score' => 0.9 );
$r            = GFAPI::submit_form( $volunteer_id, $volunteer_input( 'tok-v-ok' ), array(), 0, 2 );
$entry        = ! empty( $r['entry_id'] ) ? GFAPI::get_entry( $r['entry_id'] ) : null;
$chk( '2 passing score: entry active, not spam', is_array( $entry ) && 'active' === $entry['status'], is_array( $entry ) ? $entry['status'] : 'no entry' );

// --- 3. Volunteer: the filter restores the old refusal ------------------------
$reset_post();
add_filter( 'gswp_gf_low_score_as_spam', '__return_false' );
$calls0       = $stub['calls'];
$stub['next'] = array( 'score' => 0.3 );
$r            = GFAPI::validate_form( $volunteer_id, $volunteer_input( 'tok-v-filter' ), array(), 0, 2 );
remove_filter( 'gswp_gf_low_score_as_spam', '__return_false' );
$chk( '3 gswp_gf_low_score_as_spam=false refuses as before', empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0 );

// --- 4. Stripe pre-check: one assessment, with transactionData ----------------
$reset_post();
$as_precheck( true );
$_POST['action'] = 'gfstripe_validate_form';
$calls0          = $stub['calls'];
$stub['next']    = array( 'score' => 0.9, 'risk' => 0.05 );
$r               = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-ok' ) );
$sent            = end( $stub['bodies'] );
$txn             = isset( $sent['event']['transactionData'] ) ? $sent['event']['transactionData'] : null;
$chk( '4 pre-check passes', ! empty( $r['is_valid'] ), wp_json_encode( $r['validation_messages'] ) );
$chk( '4 exactly one assessment', 1 === $stub['calls'] - $calls0 );
$chk( '4 transactionData sent', is_array( $txn ) );
$chk( '4 billing region resolved from the Address field', is_array( $txn ) && isset( $txn['billingAddress']['regionCode'] ) && 'US' === $txn['billingAddress']['regionCode'], is_array( $txn ) ? wp_json_encode( $txn['billingAddress'] ) : '' );
$chk( '4 postal code sent', is_array( $txn ) && '78201' === $txn['billingAddress']['postalCode'] );
$chk( '4 order value sent', is_array( $txn ) && abs( (float) $txn['value'] - 5.0 ) < 0.001, is_array( $txn ) ? (string) $txn['value'] : '' );
$chk( '4 customer email sent', is_array( $txn ) && isset( $txn['user']['email'] ) && 'qa-t34-payer@onedog.solutions' === $txn['user']['email'] );
$precheck_name = 'projects/test/assessments/t34-' . $stub['calls'];

// --- 5. Completion request redeems the verdict, no second assessment ----------
$reset_post();
$as_precheck( false );
$prop->setValue( $provider, array() );
$calls0 = $stub['calls'];
$r      = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-ok' ) );
$pa     = $prop->getValue( $provider );
$chk( '5 completion admitted', ! empty( $r['is_valid'] ) );
$chk( '5 no second call to Google (no DUPE)', 0 === $stub['calls'] - $calls0, ( $stub['calls'] - $calls0 ) . ' calls' );
$chk( '5 pre-check assessment carried to the entry', isset( $pa[ $stripe_id ] ) && $precheck_name === $pa[ $stripe_id ], isset( $pa[ $stripe_id ] ) ? $pa[ $stripe_id ] : 'none' );

// --- 6. A passing verdict is single use ----------------------------------------
$reset_post();
$calls0       = $stub['calls'];
$stub['next'] = array( 'valid' => false, 'reason' => 'DUPE' );
$r            = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-ok' ) );
$chk( '6 replaying the token afterwards is assessed again and refused', empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0 );

// --- 7. A failed pre-check: the re-post shows the real reason ------------------
$reset_post();
$as_precheck( true );
$_POST['action'] = 'gfstripe_validate_form';
$calls0          = $stub['calls'];
$stub['next']    = array( 'score' => 0.2 );
$r               = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-low' ) );
$chk( '7 low score, no fraud verdict: pre-check refuses the payment', empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0, wp_json_encode( $r['validation_messages'] ) );
$precheck_msg = $err( $stripe_id );
$reset_post();
$as_precheck( false );
$calls0       = $stub['calls'];
$stub['next'] = array( 'valid' => false, 'reason' => 'DUPE' );
$r            = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-low' ) );
$chk( '7 native re-post refused without a second call', empty( $r['is_valid'] ) && 0 === $stub['calls'] - $calls0 );

// --- 7b. The re-post carries a FRESH token: still the pre-check's refusal ------
// v2.31.1. The bootstrap's re-mint can land before GF Stripe's native re-post,
// so the re-post carries a new token with no verdict of its own. The companion
// field gswp_gf_spent names the token the pre-check refused (tok-s-low, §7).
$reset_post();
$as_precheck( false );
$calls0       = $stub['calls'];
$stub['next'] = array( 'score' => 0.9 );
$r            = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-fresh', 'gswp_gf_spent' => 'tok-s-low' ) );
$chk( '7b re-post with fresh token + spent=refused token: refused, no call', empty( $r['is_valid'] ) && 0 === $stub['calls'] - $calls0 );
$chk( '7b the replayed message is exactly the pre-check\'s', '' !== $precheck_msg && $err( $stripe_id ) === $precheck_msg, $err( $stripe_id ) );

// A spent token with no verdict falls through to ordinary scoring.
$reset_post();
$calls0       = $stub['calls'];
$stub['next'] = array( 'score' => 0.2 );
$r            = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-fresh2', 'gswp_gf_spent' => 'tok-s-bogus' ) );
$chk( '7b unknown spent token: fresh token is assessed', 1 === $stub['calls'] - $calls0 );

// A spent PASS never admits anything, and is not consumed.
$reset_post();
$as_precheck( true );
$_POST['action'] = 'gfstripe_validate_form';
$stub['next']    = array( 'score' => 0.9 );
$r               = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-ok2' ) );
$chk( '7b setup: pre-check for tok-s-ok2 passes', ! empty( $r['is_valid'] ) );
$reset_post();
$as_precheck( false );
$calls0       = $stub['calls'];
$stub['next'] = array( 'score' => 0.2 );
$r            = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-x', 'gswp_gf_spent' => 'tok-s-ok2' ) );
$chk( '7b spent=passing token does not admit: fresh token assessed and refused', empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0 );
$chk( '7b the passing verdict is still held (not consumed)', false !== get_transient( GSWP_Provider_Gravity_Forms::PRECHECK_PREFIX . substr( hash( 'sha256', 'tok-s-ok2' ), 0, 32 ) ) );

// Retry after a declined card: the next attempt is a PRE-CHECK, which never
// replays — it scores its own fresh token even though spent names a refusal.
$reset_post();
$as_precheck( true );
$_POST['action'] = 'gfstripe_validate_form';
$calls0          = $stub['calls'];
$stub['next']    = array( 'score' => 0.9 );
$r               = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-retry', 'gswp_gf_spent' => 'tok-s-low' ) );
$chk( '7b pre-check ignores spent: retry is assessed and passes', ! empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0 );
$as_precheck( false );

// Form-bound: the Stripe form's refusal does not replay on another form.
$reset_post();
$calls0       = $stub['calls'];
$stub['next'] = array( 'score' => 0.9 );
$r            = GFAPI::validate_form( $volunteer_id, $volunteer_input( 'tok-v-cross' ) + array( 'gswp_gf_spent' => 'tok-s-low' ), array(), 0, 2 );
$chk( '7b spent verdict from another form is ignored', ! empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0 );

// --- 8. Low score + cleared fraud verdict now admits a Stripe payment ----------
$reset_post();
$as_precheck( true );
$_POST['action'] = 'gfstripe_validate_form';
$stub['next']    = array( 'score' => 0.2, 'risk' => 0.1 );
$r               = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-vpn' ) );
$chk( '8 low score but transactionRisk 0.10 is admitted (2.28.0 rule now reachable)', ! empty( $r['is_valid'] ) );

// --- 9. Carding shape is still refused -----------------------------------------
$reset_post();
update_option( 'gswp_txn_block', '1' );
$_POST['action'] = 'gfstripe_validate_form';
$calls0          = $stub['calls'];
$stub['next']    = array( 'score' => 0.1, 'risk' => 0.95 );
$r               = GFAPI::validate_form( $stripe_id, $stripe_input + array( 'gswp_gf_token' => 'tok-s-card' ) );
$chk( '9 low score + high transactionRisk is refused', empty( $r['is_valid'] ) && 1 === $stub['calls'] - $calls0 );
$as_precheck( false );

// --- Cleanup ------------------------------------------------------------------
remove_filter( 'pre_http_request', $http, 10 );
GFAPI::delete_form( $volunteer_id );
GFAPI::delete_form( $stripe_id );
foreach ( array( 'tok-s-ok', 'tok-s-low', 'tok-s-vpn', 'tok-s-card', 'tok-s-ok2', 'tok-s-retry' ) as $tok ) {
	delete_transient( GSWP_Provider_Gravity_Forms::PRECHECK_PREFIX . substr( hash( 'sha256', $tok ), 0, 32 ) );
}
foreach ( $saved as $opt => $val ) {
	if ( null === $val ) {
		delete_option( $opt );
	} else {
		update_option( $opt, $val, false );
	}
}
delete_transient( 'gswp_gf_no_txn_' . (int) $stripe_id );
$_POST = array();

printf( "\n%s — %d failure(s).\n", 0 === $fail ? 'ALL PASS' : 'FAILURES', $fail );
