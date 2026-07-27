<?php
/**
 * GF replacement verification — chunk 2: render coverage (v2.20.0)
 *
 * THE MOST IMPORTANT CHUNK. Renders every Gravity Form server-side, through
 * the same shortcode path the front end uses, and checks that our token field
 * actually ends up in the markup.
 *
 * This answers the question that decides whether replacement is safe: with
 * Gravity Forms' own reCAPTCHA switched off, a form we fail to inject into is
 * submitted with no bot protection at all. Rendering here exercises the real
 * hooks (gform_submit_button and the gform_get_form_filter fallback), so a
 * missed render path shows up as a FAIL rather than as silence.
 *
 * Each form is rendered twice — non-AJAX and AJAX — because they take
 * different paths through Gravity Forms.
 *
 * MUTATES: rendering records a successful injection in the plugin's coverage
 * log, exactly as a real page view would. That is intended. Note that it means
 * a server-side pass will show as "token seen" in the settings panel even if a
 * real browser render would differ, so treat a browser spot-check of one form
 * as still worthwhile.
 *
 * Run via an MCP PHP-execution tool or `wp eval-file`. Requires chunk 11 to
 * have passed.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'GSWP_Form_Provider_Registry' ) || ! class_exists( 'GFAPI' ) ) {
	echo "STOP: run chunk 11 first — plugin or Gravity Forms not available.\n";
	return;
}

// Run context. Printed by every chunk so a result can always be tied to the
// plugin version and site that produced it — two earlier rounds were read
// against the wrong version because the output carried no provenance.
$gswp_ctx = array(
	'=== RUN CONTEXT ===',
	'  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ),
	'  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ),
	'  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ),
	'  php            : ' . PHP_VERSION,
	'',
);
echo implode( "\n", $gswp_ctx ) . "\n";

$provider = GSWP_Form_Provider_Registry::get( 'gravity-forms' );
$on       = GSWP_Form_Provider_Registry::is_on( 'gravity-forms' );

$out   = array();
$out[] = '=== GF render coverage ===';
$out[] = 'Replacement is currently: ' . ( $on ? 'ON' : 'OFF' );

if ( ! $on ) {
	$out[] = '';
	$out[] = 'Replacement is OFF, so no token fields are expected. Turn it on in';
	$out[] = 'Settings > Google Security > Form Protection, then re-run this chunk.';
	echo implode( "\n", $out ) . "\n";
	return;
}

$token_field  = GSWP_Provider_Gravity_Forms::TOKEN_FIELD;
$forms        = $provider->forms();
$pass         = 0;
$fail         = 0;
$skip         = 0;
$failed_forms = array();

$out[] = '';
$out[] = str_pad( 'FORM', 34 ) . str_pad( 'MODE', 10 ) . str_pad( 'TOKEN', 8 ) . str_pad( 'GF CAPTCHA', 12 ) . 'NOTE';
$out[] = str_repeat( '-', 88 );

foreach ( $forms as $form_id => $title ) {
	$eligible = $provider->form_is_eligible( $form_id );

	if ( ! $eligible ) {
		++$skip;
		$out[] = str_pad( '#' . $form_id . ' ' . mb_substr( $title, 0, 28 ), 34 )
			. str_pad( '-', 10 ) . str_pad( '-', 8 ) . str_pad( 'kept', 12 )
			. 'ineligible (v2 checkbox) — GF keeps this one, by design';
		continue;
	}

	foreach ( array( 'false', 'true' ) as $ajax ) {
		$markup = '';
		$note   = '';

		try {
			$markup = do_shortcode( '[gravityform id="' . (int) $form_id . '" title="false" description="false" ajax="' . $ajax . '"]' );
		} catch ( Throwable $e ) {
			$note = 'render threw: ' . $e->getMessage();
		}

		if ( '' === $markup && '' === $note ) {
			$note = 'rendered empty';
		}

		$has_token = false !== strpos( $markup, 'name="' . $token_field . '"' );

		// Is Gravity Forms' own reCAPTCHA still being emitted for this form?
		//
		// Our own field carries class="g-recaptcha-response", so the markup must
		// have it removed before searching or every check self-matches. An
		// earlier version guarded that with "&& ! $has_token", which silently
		// disabled the check in exactly the case that passes — every "none" it
		// printed was a false negative.
		$stripped  = preg_replace( '/<input[^>]*name="' . preg_quote( $token_field, '/' ) . '"[^>]*>/i', '', $markup );
		$gf_captcha = 'none';
		foreach ( array( 'g-recaptcha', 'grecaptcha', 'data-sitekey', 'gfield_captcha', 'ginput_recaptcha', 'recaptcha/api', 'recaptcha/enterprise' ) as $needle ) {
			if ( false !== stripos( (string) $stripped, $needle ) ) {
				$gf_captcha = 'PRESENT';
				break;
			}
		}

		if ( $has_token ) {
			++$pass;
		} else {
			++$fail;
			$failed_forms[] = '#' . $form_id . ' (' . ( 'true' === $ajax ? 'ajax' : 'standard' ) . ')';
			if ( '' === $note ) {
				$note = 'NO TOKEN FIELD — this form would submit unscored';
			}
		}

		$out[] = str_pad( '#' . $form_id . ' ' . mb_substr( $title, 0, 28 ), 34 )
			. str_pad( 'true' === $ajax ? 'ajax' : 'standard', 10 )
			. str_pad( $has_token ? 'yes' : 'NO', 8 )
			. str_pad( $gf_captcha, 12 )
			. $note;
	}
}

$out[] = '';
$out[] = sprintf( 'Renders passed: %d   failed: %d   forms skipped as ineligible: %d', $pass, $fail, $skip );

if ( $fail > 0 ) {
	$out[] = '';
	$out[] = '*** COVERAGE GAP ***';
	$out[] = 'These renders produced no token field: ' . implode( ', ', $failed_forms );
	$out[] = '';
	$out[] = 'With replacement ON, Gravity Forms own reCAPTCHA is switched off, so';
	$out[] = 'those forms currently have NO bot protection. Either turn Form';
	$out[] = 'Protection off (which restores GF reCAPTCHA on the next page load) or';
	$out[] = 'report this so the injection hooks can be corrected.';
} else {
	$out[] = '';
	$out[] = 'All eligible forms received a token field on both render paths.';
}

$out[] = '';
$out[] = 'Report the whole block above verbatim, including the table.';

echo implode( "\n", $out ) . "\n";
