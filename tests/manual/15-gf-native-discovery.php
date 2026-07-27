<?php
/**
 * GF replacement verification — chunk 5: native reCAPTCHA discovery (v2.20.3)
 *
 * Read-only. Finds out what Gravity Forms' own reCAPTCHA actually is on this
 * site, because guessing has now failed twice.
 *
 * Chunk 14 reported `GF own captcha: unknown` while `data-sitekey` was present
 * in every rendered form. Both facts have the same cause: the option name this
 * plugin looks for is wrong, so it can neither detect GF's reCAPTCHA nor
 * disable it. `disable_native()` filters an option that does not exist.
 *
 * Nothing here is fixed by inference. This prints the evidence needed to
 * correct the binding:
 *
 *   1. every option in the database whose name looks like it could hold GF
 *      reCAPTCHA settings, with key values masked;
 *   2. the markup surrounding each `data-sitekey`, so the element and its
 *      classes identify which reCAPTCHA type is being rendered;
 *   3. whether the key GF is rendering is the same as this plugin's.
 *
 * That third point matters most: if the keys differ, this site currently has
 * the exact divergent-key condition that broke the Stripe payment element in
 * the first place.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'GSWP_Form_Provider_Registry' ) || ! class_exists( 'GFAPI' ) ) {
	echo "STOP: run chunk 11 first.\n";
	return;
}

global $wpdb;

$provider = GSWP_Form_Provider_Registry::get( 'gravity-forms' );
$our_key  = GSWP_Recaptcha_Loader::site_key();

$mask = function ( $value ) {
	$value = (string) $value;
	if ( strlen( $value ) <= 10 ) {
		return $value;
	}
	return substr( $value, 0, 6 ) . '…' . substr( $value, -4 );
};

$out   = array();
$out[] = '=== GF native reCAPTCHA discovery ===';
$out[] = 'This plugin\'s site key: ' . ( '' === $our_key ? '(none)' : $mask( $our_key ) );
$out[] = 'Key type: ' . get_option( 'gswp_key_type', 'classic' );
$out[] = '';

// -------------------------------------------------------------------------
$out[] = '1. Candidate options in the database';
$out[] = '';

$rows = $wpdb->get_results(
	"SELECT option_name FROM {$wpdb->options}
	  WHERE option_name LIKE '%recaptcha%'
	     OR option_name LIKE '%captcha%'
	     OR option_name LIKE 'gravityformsaddon%'
	  ORDER BY option_name",
	ARRAY_A
);

if ( empty( $rows ) ) {
	$out[] = '  (none found)';
} else {
	foreach ( $rows as $row ) {
		$name  = $row['option_name'];
		$value = get_option( $name );

		$out[] = '  ' . $name;

		if ( is_array( $value ) ) {
			foreach ( $value as $k => $v ) {
				if ( is_scalar( $v ) ) {
					$looks_like_key = is_string( $v ) && strlen( $v ) > 20 && preg_match( '/^[A-Za-z0-9_\-]+$/', $v );
					$shown          = $looks_like_key ? $mask( $v ) : ( is_bool( $v ) ? var_export( $v, true ) : (string) $v );
					$out[]          = '      ' . $k . ' = ' . $shown;

					// Flag any value that equals our key or looks like a site key.
					if ( '' !== $our_key && (string) $v === $our_key ) {
						$out[] = '        ^^ this is THIS PLUGIN\'S key';
					}
				} else {
					$out[] = '      ' . $k . ' = (' . gettype( $v ) . ')';
				}
			}
		} elseif ( is_scalar( $value ) ) {
			$out[] = '      (scalar) ' . $mask( (string) $value );
		} else {
			$out[] = '      (' . gettype( $value ) . ')';
		}
		$out[] = '';
	}
}

// -------------------------------------------------------------------------
$out[] = '2. What is actually rendered';
$out[] = '';

$token       = GSWP_Provider_Gravity_Forms::TOKEN_FIELD;
$seen_keys   = array();
$forms       = $provider->forms();
$first_only  = true;

foreach ( $forms as $form_id => $title ) {
	$markup = '';
	try {
		$markup = do_shortcode( '[gravityform id="' . (int) $form_id . '" title="false" description="false" ajax="false"]' );
	} catch ( Throwable $e ) {
		$markup = '';
	}

	if ( '' === $markup ) {
		continue;
	}

	$stripped = preg_replace( '/<input[^>]*name="' . preg_quote( $token, '/' ) . '"[^>]*>/i', '', $markup );

	// Pull out every data-sitekey and the element carrying it.
	if ( preg_match_all( '/data-sitekey=["\']([^"\']+)["\']/i', (string) $stripped, $m, PREG_OFFSET_CAPTURE ) ) {
		foreach ( $m[1] as $i => $hit ) {
			$key    = $hit[0];
			$offset = max( 0, $m[0][ $i ][1] - 220 );
			$excerpt = substr( (string) $stripped, $offset, 440 );
			$excerpt = preg_replace( '/\s+/', ' ', $excerpt );

			$seen_keys[ $key ] = true;

			$out[] = '  form #' . $form_id . ' — sitekey ' . $mask( $key )
				. ( '' !== $our_key && $key === $our_key ? '  [SAME as this plugin]' : '  [DIFFERENT from this plugin]' );

			if ( $first_only ) {
				$out[]      = '    markup around it:';
				$out[]      = '    ' . $excerpt;
				$first_only = false;
			}
		}
	}

	// Any script tags left that load reCAPTCHA.
	if ( preg_match_all( '/<script[^>]+src=["\']([^"\']*recaptcha[^"\']*)["\']/i', (string) $stripped, $sm ) ) {
		foreach ( array_unique( $sm[1] ) as $src ) {
			$out[] = '  form #' . $form_id . ' — loader script: ' . $src;
		}
	}
}

if ( empty( $seen_keys ) ) {
	$out[] = '  (no data-sitekey found in any rendered form)';
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '3. Verdict';
$out[] = '';
$out[] = '  This plugin reports GF captcha state as: ' . $provider->native_captcha_state( 1 );

$divergent = false;
foreach ( array_keys( $seen_keys ) as $key ) {
	if ( '' !== $our_key && $key !== $our_key ) {
		$divergent = true;
	}
}

if ( $divergent ) {
	$out[] = '';
	$out[] = '  *** DIVERGENT KEYS ON THIS SITE RIGHT NOW ***';
	$out[] = '  Gravity Forms is rendering a reCAPTCHA for a different site key';
	$out[] = '  than this plugin uses. Only one site key can be pre-rendered per';
	$out[] = '  page, so one of the two will fail to execute. This is the exact';
	$out[] = '  condition that broke the Stripe payment element originally.';
	$out[] = '';
	$out[] = '  Check wp-admin for the conflict notice — it should be naming both';
	$out[] = '  keys. If it is not, that warning path is broken too.';
} elseif ( ! empty( $seen_keys ) ) {
	$out[] = '  Keys match, so the two loaders share one script and coexist.';
	$out[] = '  disable_native() still failed, so the site is paying for two';
	$out[] = '  assessments per submission rather than one.';
}

$out[] = '';
$out[] = 'WHAT TO REPORT: the whole block, especially section 1 (the option name';
$out[] = 'that actually holds GF\'s reCAPTCHA settings) and the markup excerpt in';
$out[] = 'section 2. Those two pieces are what fix the binding.';

echo implode( "\n", $out ) . "\n";
