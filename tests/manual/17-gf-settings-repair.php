<?php
/**
 * GF replacement verification — chunk 7: repair Gravity Forms' reCAPTCHA settings
 *
 * DIAGNOSTIC BY DEFAULT. Nothing is written unless $gswp_apply is set to true.
 *
 * Versions 2.20.0–2.20.4 of this plugin filtered Gravity Forms' reCAPTCHA
 * settings option on admin screens as well as the front end. The add-on's
 * settings page reads that option to populate its fields and saves back what it
 * read, so it persisted the blanked values. On the affected site the stored
 * array was left holding only `connection_type`, `nonce` and `action` — the
 * last two being the settings form's own posted fields, which is the signature
 * of exactly that bad save.
 *
 * That array is not merely missing keys, it is malformed, and Gravity Forms
 * renders its settings page from it. Re-entering keys into a page built from a
 * malformed array does not necessarily work, which matches the report that the
 * page stays unusable even with this plugin deactivated.
 *
 * This chunk shows what is actually there, who (if anyone) is still filtering
 * it, and can then back the option up and delete it so Gravity Forms rebuilds
 * a clean one on the next page load.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ---------------------------------------------------------------------------
// Set this to true to APPLY the repair. Leave false to see what it would do.
$gswp_apply = false;
// ---------------------------------------------------------------------------

global $wpdb, $wp_filter;

$option = 'gravityformsaddon_gravityformsrecaptcha_settings';

$mask = function ( $value ) {
	$value = (string) $value;
	if ( '' === $value ) {
		return '(EMPTY STRING)';
	}
	if ( strlen( $value ) <= 10 ) {
		return $value;
	}
	return substr( $value, 0, 6 ) . '…' . substr( $value, -4 );
};

$out   = array();
$out[] = '=== RUN CONTEXT ===';
$out[] = '  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE (this is expected here)' );
$out[] = '  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST );
$out[] = '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' );
$out[] = '  php            : ' . PHP_VERSION;
$out[] = '  mode           : ' . ( $gswp_apply ? '*** APPLY — THIS WILL WRITE ***' : 'dry run (nothing will be written)' );
$out[] = '';

// -------------------------------------------------------------------------
$out[] = '1. What is stored right now (read straight from the database)';
$out[] = '';

$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_value, autoload FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

$stored = null;

if ( null === $row ) {
	$out[] = '  The option does not exist. Gravity Forms will treat the add-on as';
	$out[] = '  never configured and render a fresh settings page. If the page is';
	$out[] = '  still unusable in that state, the cause is not this option.';
} else {
	$stored = maybe_unserialize( $row['option_value'] );
	$out[]  = '  autoload: ' . $row['autoload'];

	if ( ! is_array( $stored ) ) {
		$out[] = '  *** NOT AN ARRAY — type ' . gettype( $stored ) . ' ***';
		$out[] = '  Gravity Forms expects an array here. This alone would break the';
		$out[] = '  settings page.';
	} else {
		foreach ( $stored as $k => $v ) {
			if ( is_scalar( $v ) ) {
				$looks_like_key = is_string( $v ) && strlen( $v ) > 20;
				$out[]          = '  ' . str_pad( (string) $k, 28 ) . ( $looks_like_key ? $mask( (string) $v ) : var_export( $v, true ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			} else {
				$out[] = '  ' . str_pad( (string) $k, 28 ) . '(' . gettype( $v ) . ')';
			}
		}

		$expected = array( 'site_key_v3', 'secret_key_v3', 'score_threshold_v3', 'recaptcha_keys_status_v3' );
		$missing  = array();
		foreach ( $expected as $k ) {
			if ( ! array_key_exists( $k, $stored ) ) {
				$missing[] = $k;
			}
		}

		$junk = array_intersect( array( 'nonce', 'action', '_wpnonce', '_wp_http_referer', 'gform-settings-save' ), array_keys( $stored ) );

		$out[] = '';
		$out[] = '  missing v3 settings : ' . ( empty( $missing ) ? 'none' : implode( ', ', $missing ) );
		$out[] = '  form fields stored  : ' . ( empty( $junk ) ? 'none' : implode( ', ', $junk ) . '   <- signature of a bad save' );
	}
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '2. Is anything still filtering this option?';
$out[] = '';

$describe = function ( $cb ) {
	if ( is_string( $cb ) ) {
		return $cb . '()';
	}
	if ( is_array( $cb ) && 2 === count( $cb ) ) {
		$class = is_object( $cb[0] ) ? get_class( $cb[0] ) : (string) $cb[0];
		return $class . '::' . (string) $cb[1] . '()';
	}
	if ( $cb instanceof Closure ) {
		return '(closure)';
	}
	return '(' . gettype( $cb ) . ')';
};

$any_filter = false;
foreach ( array( 'option_' . $option, 'pre_option_' . $option, 'pre_update_option_' . $option, 'default_option_' . $option ) as $hook ) {
	if ( ! isset( $wp_filter[ $hook ] ) ) {
		continue;
	}
	foreach ( $wp_filter[ $hook ]->callbacks as $priority => $callbacks ) {
		foreach ( $callbacks as $cb ) {
			$any_filter = true;
			$out[]      = '  ' . $hook . '  @' . $priority . '  ' . $describe( $cb['function'] );
		}
	}
}

if ( ! $any_filter ) {
	$out[] = '  Nothing. No plugin is intercepting this option on this request.';
	$out[] = '  Whatever is wrong with the settings page is in the stored value or';
	$out[] = '  in Gravity Forms itself, not in a filter.';
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '3. Gravity Forms reCAPTCHA add-on';
$out[] = '';

// Ask Gravity Forms which add-ons it has registered rather than testing a
// guessed class name. The add-on class is namespaced
// (Gravity_Forms\Gravity_Forms_RECAPTCHA\GF_RECAPTCHA), so the unqualified
// class_exists() this section used to do reported "not loaded" for an add-on
// that was active the whole time.
$addon_class = '';

if ( class_exists( 'GFAddOn' ) ) {
	foreach ( GFAddOn::get_registered_addons() as $class ) {
		if ( false !== stripos( $class, 'recaptcha' ) ) {
			$addon_class = $class;
			break;
		}
	}
	$out[] = '  add-on class : ' . ( '' === $addon_class ? 'not registered with Gravity Forms' : $addon_class );
} else {
	$out[] = '  add-on class : cannot tell — Gravity Forms core is not loaded on this request';
}

if ( '' !== $addon_class && is_callable( array( $addon_class, 'get_instance' ) ) ) {
	$instance = call_user_func( array( $addon_class, 'get_instance' ) );
	if ( is_object( $instance ) && method_exists( $instance, 'get_version' ) ) {
		$out[] = '  version      : ' . $instance->get_version();
	}
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '4. Repair';
$out[] = '';

if ( null === $row ) {
	$out[] = '  Nothing to repair — the option is already absent.';
} elseif ( ! $gswp_apply ) {
	$out[] = '  WOULD DO:';
	$out[] = '    a. copy the current value to gswp_gf_recaptcha_backup (autoload no)';
	$out[] = '    b. delete ' . $option;
	$out[] = '    c. flush the object cache';
	$out[] = '';
	$out[] = '  Deleting rather than rewriting is deliberate. Gravity Forms owns the';
	$out[] = '  shape of that array and this plugin should not be guessing it — the';
	$out[] = '  add-on rebuilds it correctly the first time its settings page is';
	$out[] = '  saved. The backup makes this reversible.';
	$out[] = '';
	$out[] = '  To apply: change $gswp_apply at the top of this file to true and';
	$out[] = '  run it once more.';
} else {
	$backup = array(
		'option'  => $option,
		'value'   => $stored,
		'raw'     => $row['option_value'],
		'time'    => gmdate( 'c' ),
		'reason'  => 'Corrupted by Google Security for WordPress 2.20.0-2.20.4; reset before reconfiguring.',
	);

	update_option( 'gswp_gf_recaptcha_backup', $backup, false );
	$out[] = '  a. backed up to gswp_gf_recaptcha_backup';

	$deleted = delete_option( $option );
	$out[] = '  b. delete ' . $option . ' : ' . ( $deleted ? 'done' : 'FAILED' );

	if ( function_exists( 'wp_cache_flush' ) ) {
		wp_cache_flush();
		$out[] = '  c. object cache flushed';
	}

	$after = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$out[] = '';
	$out[] = '  verified: option is now ' . ( null === $after ? 'ABSENT (as intended)' : 'STILL PRESENT — repair did not take' );
	$out[] = '';
	$out[] = '  NEXT:';
	$out[] = '    1. Hard-reload Forms -> Settings -> reCAPTCHA (bypass browser cache).';
	$out[] = '    2. Enter the site key and secret, connection type classic,';
	$out[] = '       score threshold 0.5, and save.';
	$out[] = '    3. Run chunk 16 to confirm the values persisted.';
	$out[] = '';
	$out[] = '  Do NOT reactivate Google Security for WordPress below 2.20.5.';
	$out[] = '  On 2.20.4 and earlier the settings page will empty the keys again.';
}

$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
