<?php
// GSWP manual test 33 — READ-ONLY evidence dump for a site whose Gravity Forms
// visitors are being refused ("did not pass our automated security check") or
// whose Gravity Forms Stripe payments are failing.
//
// Run with: wp eval-file tests/manual/33-gf-rejection-evidence.php
// or paste into an MCP PHP-execution tool. Writes nothing.
//
// Written for v2.31.0 after a volunteer applicant on a live Gravity Forms site
// reported being refused on every attempt, refresh or not, and the same site
// reported failing Stripe payments. That message has exactly one source: a
// reCAPTCHA score below the form's threshold. A refresh cannot cure a score, so
// the question this file answers is WHY the scores are low and WHICH path
// refused the payment — not whether the token reached the server.
//
// Secrets are never printed: keys are reported as set/empty only.

$h = function ( $title ) {
	printf( "\n=== %s ===\n", $title );
};
$kv = function ( $k, $v ) {
	printf( "  %-38s %s\n", $k, is_scalar( $v ) || null === $v ? var_export( $v, true ) : wp_json_encode( $v ) );
};

$h( 'Plugin and keys' );
$kv( 'gswp version', defined( 'GSWP_VERSION' ) ? GSWP_VERSION : get_option( 'gswp_db_version' ) );
$kv( 'key type', get_option( 'gswp_key_type', 'classic' ) );
$kv( 'site key set', '' !== get_option( 'gswp_site_key', '' ) );
$kv( 'txn defense', get_option( 'gswp_txn_defense', '0' ) );
$kv( 'txn block', get_option( 'gswp_txn_block', '0' ) );
$kv( 'GF provider on', class_exists( 'GSWP_Form_Provider_Registry' ) ? GSWP_Form_Provider_Registry::is_on( 'gravity-forms' ) : 'n/a' );
foreach ( array( 'gf_submit', 'gf_register', 'gf_account_update', 'gf_password', 'checkout', 'txn' ) as $ctx ) {
	$kv( "threshold {$ctx}", get_option( 'gswp_threshold_' . $ctx, '(default)' ) );
}

$h( 'Visitor IP resolution (what Google receives as userIpAddress)' );
$kv( 'REMOTE_ADDR (this request)', isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : null );
foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_QC_POP', 'HTTP_CDN_LOOP', 'SERVER_SOFTWARE' ) as $hdr ) {
	$kv( $hdr, isset( $_SERVER[ $hdr ] ) ? $_SERVER[ $hdr ] : null );
}
$kv( 'trusted proxies', get_option( 'gswp_trusted_proxies', '' ) );
$kv( 'client IP header', get_option( 'gswp_client_ip_header', '' ) );
$kv( 'trust Cloudflare', get_option( 'gswp_trusted_cloudflare', '0' ) );
$kv( 'trust QUIC.cloud', get_option( 'gswp_trusted_quiccloud', '0' ) );
if ( class_exists( 'GSWP_Client_IP' ) ) {
	$addr = GSWP_Client_IP::remote_addr();
	$kv( 'resolved client IP', GSWP_Client_IP::get() );
	foreach ( array( 'cloudflare', 'quiccloud' ) as $cdn ) {
		$ranges = GSWP_Client_IP::default_cdn_ranges( $cdn );
		$stored = GSWP_Client_IP::cdn_ranges( $cdn );
		$all    = array_merge( is_array( $ranges ) ? $ranges : array(), is_array( $stored ) ? $stored : array() );
		$kv( "REMOTE_ADDR is a {$cdn} edge", $addr && GSWP_Client_IP::matches( $addr, $all ) );
	}
}
echo "  NOTE: wp-cli has no visitor. Re-run this block from a front-end request (MCP tool) to see real proxy headers.\n";

$h( 'Script-delay / page-cache plugins that can starve reCAPTCHA of signals' );
$active = (array) get_option( 'active_plugins', array() );
foreach ( $active as $p ) {
	if ( preg_match( '/litespeed|wp-rocket|perfmatters|flying|autoptimize|w3-total|sg-cachepress|simple-performance|cache|optimi[sz]e|delay/i', $p ) ) {
		$kv( 'active', $p );
	}
}
foreach ( array( 'litespeed.conf.optm-js_delay_inc', 'litespeed.conf.optm-js_defer', 'litespeed.conf.optm-js_defer_exc', 'litespeed.conf.cache' ) as $opt ) {
	$v = get_option( $opt, null );
	if ( null !== $v ) {
		$kv( $opt, $v );
	}
}

$h( 'Gravity Forms: classification, coverage, last rejection' );
if ( ! class_exists( 'GFAPI' ) ) {
	echo "  Gravity Forms not active.\n";
} else {
	$provider   = class_exists( 'GSWP_Form_Provider_Registry' ) ? GSWP_Form_Provider_Registry::get( 'gravity-forms' ) : null;
	$injections = (array) get_option( 'gswp_gf_injection_log', array() );
	$rejections = (array) get_option( 'gswp_gf_last_rejection', array() );
	foreach ( GFAPI::get_forms() as $form ) {
		$id    = (int) $form['id'];
		$feeds = GFAPI::get_feeds( null, $id );
		$feeds = is_array( $feeds ) ? $feeds : array();
		printf( "  #%d %s\n", $id, $form['title'] );
		$kv( '    feeds', array_map( function ( $f ) { return $f['addon_slug'] . ( $f['is_active'] ? '' : '(off)' ); }, $feeds ) );
		$kv( '    pages', 1 + count( array_filter( $form['fields'], function ( $f ) { return 'page' === $f->type; } ) ) );
		if ( $provider && method_exists( $provider, 'form_policy' ) ) {
			$kv( '    policy', $provider->form_policy( $id ) );
			$kv( '    strict', $provider->form_is_strict( $id ) );
		}
		$kv( '    last injection', isset( $injections[ $id ] ) ? gmdate( 'Y-m-d H:i:s', (int) $injections[ $id ] ) . ' UTC' : 'never' );
		$kv( '    last rejection', isset( $rejections[ $id ] ) ? $rejections[ $id ]['reason'] . ' @ ' . gmdate( 'Y-m-d H:i:s', (int) $rejections[ $id ]['time'] ) . ' UTC' : 'none' );
		foreach ( $feeds as $f ) {
			if ( 'gravityformsstripe' !== $f['addon_slug'] ) {
				continue;
			}
			$billing = array();
			foreach ( (array) $f['meta'] as $mk => $mv ) {
				if ( 0 === strpos( $mk, 'billingInformation_' ) ) {
					$billing[ substr( $mk, 19 ) ] = '' !== (string) $mv ? 'mapped' : '-';
				}
			}
			$kv( '    stripe feed billing map', $billing ? $billing : 'NONE (Transaction defense gets no transactionData)' );
			$kv( '    stripe transactionType', isset( $f['meta']['transactionType'] ) ? $f['meta']['transactionType'] : null );
		}
	}
	$stripe = get_option( 'gravityformsaddon_gravityformsstripe_settings' );
	if ( is_array( $stripe ) ) {
		$kv( 'Stripe api_mode', isset( $stripe['api_mode'] ) ? $stripe['api_mode'] : null );
		$kv( 'Stripe checkout_method', isset( $stripe['checkout_method'] ) ? $stripe['checkout_method'] : null );
	}
}

$h( 'Plugin log tail (newest first) — score lines are the evidence' );
$tail = class_exists( 'GSWP_Log' ) ? GSWP_Log::tail( 50 ) : array();
foreach ( $tail as $row ) {
	printf( "  %s [%s] %s\n", gmdate( 'Y-m-d H:i:s', (int) $row['time'] ), $row['level'], $row['message'] );
}
if ( ! $tail ) {
	echo "  (empty)\n";
}

$h( 'Next: reCAPTCHA Enterprise console / Cloud Logging for this site key' );
echo "  For actions 'submit' and 'checkout': score histogram, riskAnalysis.reasons,\n";
echo "  and userIpAddress vs. the visitor IP GF recorded on the entry (a CDN edge IP\n";
echo "  there means trusted proxies are not configured).\n";
