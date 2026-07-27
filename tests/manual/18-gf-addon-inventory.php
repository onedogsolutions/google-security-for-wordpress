<?php
/**
 * GF replacement verification — chunk 8: Gravity Forms add-on inventory
 *
 * Read-only. Nothing is written.
 *
 * Chunk 17 reported the reCAPTCHA add-on class as "NOT LOADED", but that check
 * guessed at three unqualified class names — and PHP class names are
 * case-insensitive, so it really tested only two. Modern Gravity Forms add-ons
 * are namespaced, which an unqualified class_exists() can never match. The
 * result is therefore unreliable, and guessing Gravity Forms identifiers has
 * now failed three times in this investigation.
 *
 * This enumerates instead. It asks WordPress and Gravity Forms what is actually
 * installed, active and registered, rather than testing a name someone hoped
 * was right.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'get_plugins' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

$out   = array();
$out[] = '=== RUN CONTEXT ===';
$out[] = '  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' );
$out[] = '  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST );
$out[] = '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' );
$out[] = '  php            : ' . PHP_VERSION;
$out[] = '';

// -------------------------------------------------------------------------
$out[] = '1. Installed plugins matching gravity / captcha';
$out[] = '';

$active = (array) get_option( 'active_plugins', array() );

foreach ( get_plugins() as $basename => $data ) {
	if ( ! preg_match( '/gravity|captcha/i', $basename . ' ' . ( isset( $data['Name'] ) ? $data['Name'] : '' ) ) ) {
		continue;
	}

	$out[] = '  ' . ( in_array( $basename, $active, true ) ? '[ACTIVE]  ' : '[inactive]' )
		. ' ' . str_pad( isset( $data['Version'] ) ? $data['Version'] : '?', 10 )
		. ' ' . $basename;
	$out[] = '             ' . ( isset( $data['Name'] ) ? $data['Name'] : '' );
}

// Network-activated plugins live elsewhere.
if ( is_multisite() ) {
	$network = (array) get_site_option( 'active_sitewide_plugins', array() );
	foreach ( array_keys( $network ) as $basename ) {
		if ( preg_match( '/gravity|captcha/i', $basename ) ) {
			$out[] = '  [NETWORK] ' . $basename;
		}
	}
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '2. Is the reCAPTCHA add-on on disk?';
$out[] = '';

$candidates = array(
	'gravityformsrecaptcha/gravityformsrecaptcha.php',
	'gravityformsrecaptcha/recaptcha.php',
);

foreach ( $candidates as $basename ) {
	$path  = WP_PLUGIN_DIR . '/' . $basename;
	$out[] = '  ' . str_pad( $basename, 52 ) . ( file_exists( $path ) ? 'exists' : 'not found' );
}

$dir = WP_PLUGIN_DIR . '/gravityformsrecaptcha';
if ( is_dir( $dir ) ) {
	$files = glob( $dir . '/*.php' );
	$out[] = '  directory contents (top level): ' . ( empty( $files ) ? '(no php files)' : implode( ', ', array_map( 'basename', (array) $files ) ) );
} else {
	$out[] = '  plugins/gravityformsrecaptcha/ does not exist';
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '3. Add-ons Gravity Forms has registered (no guessing)';
$out[] = '';

if ( ! class_exists( 'GFAddOn' ) ) {
	$out[] = '  GFAddOn does not exist — Gravity Forms core itself is not loaded on';
	$out[] = '  this request. Nothing below can be trusted; re-run this where GF is';
	$out[] = '  loaded (a normal admin or front-end request).';
} else {
	$registered = GFAddOn::get_registered_addons();

	if ( empty( $registered ) ) {
		$out[] = '  (none registered)';
	} else {
		sort( $registered );
		foreach ( $registered as $class ) {
			$slug = '';
			if ( is_callable( array( $class, 'get_instance' ) ) ) {
				$instance = call_user_func( array( $class, 'get_instance' ) );
				if ( is_object( $instance ) ) {
					if ( method_exists( $instance, 'get_slug' ) ) {
						$slug = $instance->get_slug();
					}
					if ( '' === $slug && method_exists( $instance, 'get_short_title' ) ) {
						$slug = $instance->get_short_title();
					}
				}
			}
			$out[] = '  ' . str_pad( $slug, 34 ) . $class;
		}
	}
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '4. Every loaded class whose name mentions recaptcha';
$out[] = '';

$hits = array();
foreach ( get_declared_classes() as $class ) {
	if ( false !== stripos( $class, 'recaptcha' ) ) {
		$hits[] = $class;
	}
}

if ( empty( $hits ) ) {
	$out[] = '  (none) — no reCAPTCHA class of any kind is loaded on this request.';
} else {
	sort( $hits );
	foreach ( $hits as $class ) {
		$out[] = '  ' . $class;
	}
}

// -------------------------------------------------------------------------
$out[] = '';
$out[] = '5. Reading';
$out[] = '';
$out[] = '  If section 1 shows the reCAPTCHA add-on as [inactive], or section 2';
$out[] = '  cannot find it on disk, then the settings page is unreachable simply';
$out[] = '  because the add-on is not running — and no amount of repairing the';
$out[] = '  stored option will bring the page back. Reinstall or reactivate it';
$out[] = '  first, THEN run chunk 17.';
$out[] = '';
$out[] = '  If it is [ACTIVE] and section 3 lists it, the add-on is fine and the';
$out[] = '  malformed option is the remaining suspect — chunk 17 applies.';
$out[] = '';
$out[] = 'Report the whole block above verbatim.';

echo implode( "\n", $out ) . "\n";
