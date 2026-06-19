<?php
/**
 * Account Defender Class
 *
 * Integrates reCAPTCHA Enterprise Account Defender: reads the per-login
 * accountDefenderAssessment labels captured by the verifier, logs them,
 * optionally forces a 2FA step-up on suspicious logins, and annotates login
 * and two-factor outcomes so Google's site-specific model keeps learning.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Account_Defender {

	/**
	 * Shared verifier whose last assessment this layer interprets.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Assessment name captured for the current request's login attempt.
	 *
	 * @var string
	 */
	private static $assessment_name = '';

	/**
	 * Whether a 2FA step-up was requested for this request's login.
	 *
	 * @var bool
	 */
	private static $force_2fa = false;

	/**
	 * Whether the login outcome has already been annotated this request.
	 *
	 * @var bool
	 */
	private static $annotated = false;

	/**
	 * Constructor. Hooks the login lifecycle when the feature is active.
	 *
	 * @param GSWP_Verifier $verifier Shared verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		if ( ! self::is_active() ) {
			return;
		}

		// Runs after the verifier's login scoring (priority 30) and before the
		// 2FA enforcement (priority 100), so the labels are available to decide a
		// step-up and to seed the annotation hooks.
		add_filter( 'authenticate', array( $this, 'capture_login_assessment' ), 40, 3 );

		// Terminal login outcomes (every entry point funnels through these).
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );
	}

	/**
	 * Whether Account Defender is enabled and using an Enterprise key.
	 *
	 * @return bool
	 */
	public static function is_active() {
		return 'enterprise' === get_option( 'gswp_key_type', 'classic' )
			&& '1' === get_option( 'gswp_account_defender', '0' );
	}

	/**
	 * Capture the assessment labels for the current login and decide step-up.
	 *
	 * @param null|WP_User|WP_Error $user     Auth result so far.
	 * @param string                $username Submitted username (unused).
	 * @param string                $password Submitted password (unused).
	 * @return null|WP_User|WP_Error The unchanged $user.
	 */
	public function capture_login_assessment( $user, $username, $password ) {
		$name = $this->verifier->get_last_assessment_name();
		if ( '' === $name ) {
			return $user;
		}

		self::$assessment_name = $name;

		$labels = $this->verifier->get_last_account_labels();
		if ( ! empty( $labels ) ) {
			$this->log( 'Account Defender labels for login: ' . implode( ', ', $labels ) . '.' );
		}

		// Optional step-up: a suspicious login forces the 2FA challenge. This
		// guarantees the challenge for enrolled users (manage_options accounts are
		// enrolled by policy); users without 2FA are logged only, never blocked.
		if ( '1' === get_option( 'gswp_ad_step_up', '0' ) && in_array( 'SUSPICIOUS_LOGIN_ACTIVITY', $labels, true ) ) {
			self::$force_2fa = true;
			$this->log( 'Account Defender flagged SUSPICIOUS_LOGIN_ACTIVITY; 2FA step-up requested.' );
		}

		return $user;
	}

	/**
	 * Annotate a successful (non-2FA) login as legitimate.
	 *
	 * Held 2FA logins never reach wp_login (the challenge completes via the AJAX
	 * verifier with wp_set_auth_cookie), so this only fires for logins that
	 * finished on the password alone.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       Logged-in user.
	 */
	public function on_login_success( $user_login, $user = null ) {
		if ( self::$annotated || '' === self::$assessment_name ) {
			return;
		}
		self::$annotated = true;

		self::annotate( self::$assessment_name, 'LEGITIMATE', array( 'CORRECT_PASSWORD' ) );
	}

	/**
	 * Annotate a failed login (wrong password) for the assessed attempt.
	 *
	 * @param string        $username Submitted username.
	 * @param WP_Error|null $error    Failure reason.
	 */
	public function on_login_failed( $username, $error = null ) {
		// Our own 2FA hold surfaces as a login failure; that is not a bad
		// password, so leave it for the two-factor outcome to annotate.
		if ( $error instanceof WP_Error && 'gswp_2fa_required' === $error->get_error_code() ) {
			return;
		}

		if ( self::$annotated || '' === self::$assessment_name ) {
			return;
		}
		self::$annotated = true;

		self::annotate( self::$assessment_name, '', array( 'INCORRECT_PASSWORD' ) );
	}

	/* ---------------------------------------------------------------------
	 * Helpers used by the two-factor flow
	 * ------------------------------------------------------------------- */

	/**
	 * The assessment name captured for the current request's login.
	 *
	 * @return string
	 */
	public static function current_assessment_name() {
		return self::$assessment_name;
	}

	/**
	 * Whether a 2FA step-up was requested for the current login.
	 *
	 * @return bool
	 */
	public static function should_force_2fa() {
		return self::$force_2fa;
	}

	/**
	 * Send an annotation for an assessment to the reCAPTCHA Enterprise API.
	 *
	 * Fails open: any error is logged and ignored so the login flow is never
	 * blocked by the feedback call.
	 *
	 * @param string   $name       Assessment resource name.
	 * @param string   $annotation Annotation enum (LEGITIMATE/FRAUDULENT) or '' to omit.
	 * @param string[] $reasons    Reason enum values to include.
	 */
	public static function annotate( $name, $annotation, $reasons = array() ) {
		if ( '' === $name || ! self::is_active() ) {
			return;
		}

		$api_key = get_option( 'gswp_gcp_api_key', '' );
		if ( '' === $api_key ) {
			return;
		}

		$body = array();
		if ( '' !== $annotation ) {
			$body['annotation'] = $annotation;
		}
		if ( ! empty( $reasons ) ) {
			$body['reasons'] = array_values( $reasons );
		}
		if ( empty( $body ) ) {
			return;
		}

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/%s:annotate?key=%s',
			$name,
			rawurlencode( $api_key )
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			self::static_log( 'Account Defender annotation failed to connect: ' . $response->get_error_message() );
			return;
		}

		$status = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $status ) {
			self::static_log( 'Account Defender annotation returned HTTP ' . $status . ' (' . wp_remote_retrieve_body( $response ) . ').' );
		}
	}

	/**
	 * Log a warning to the WooCommerce logger, or the error log under WP_DEBUG.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		self::static_log( $message );
	}

	/**
	 * Static log helper shared with the annotation methods.
	 *
	 * @param string $message Log message.
	 */
	private static function static_log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $message, array( 'source' => 'gswp' ) );
		} elseif ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'GSWP Account Defender: ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
