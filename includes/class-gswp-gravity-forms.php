<?php
/**
 * Gravity Forms Detection Utility
 *
 * Reduced to a plain presence check in 2.18.0.
 *
 * Earlier versions used this class to decide whether to "defer" to Gravity
 * Forms — suppressing this plugin's own script loading, Conflict Guard and
 * token validation on any page believed to render a Gravity Form. That was
 * wrong in three ways: it treated a merely *registered* script handle as proof
 * a form was on the page (so it fired on pages with no form at all), it
 * disabled protection page-wide when Gravity Forms only ever covers its own
 * forms, and it left this plugin printing token fields it would then refuse to
 * populate — which failed submissions closed with "verification token is
 * missing".
 *
 * The real problem was never Gravity Forms. It was that nothing owned the
 * page's reCAPTCHA loader. That is now GSWP_Recaptcha_Loader's job, and it
 * works for any plugin without naming one, so none of the deferral machinery is
 * needed.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Gravity_Forms {

	/**
	 * Whether Gravity Forms is active.
	 *
	 * Retained for the settings screen, which names Gravity Forms in its
	 * compatibility guidance when it is present. Nothing in the request path
	 * branches on this any more.
	 *
	 * @return bool True when Gravity Forms is installed and active.
	 */
	public static function is_active() {
		return defined( 'GF_VERSION' ) || class_exists( 'GFForms' ) || class_exists( 'GFCommon' );
	}
}
