<?php
/**
 * Verifier Class
 *
 * Intercepts WooCommerce login, registration, and checkout actions to verify reCAPTCHA tokens.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Verifier {

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Hook into login validation.
		add_filter( 'woocommerce_process_login_errors', array( $this, 'validate_login' ), 10, 3 );

		// Hook into registration validation.
		add_filter( 'woocommerce_process_registration_errors', array( $this, 'validate_registration' ), 10, 3 );

		// Hook into checkout validation.
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'validate_checkout' ), 10, 2 );
	}

	/**
	 * Validate login request.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param string   $username         Submitted username.
	 * @param string   $password         Submitted password.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_login( $validation_error, $username, $password ) {
		if ( '1' !== get_option( 'recaptcha_woo_enable_login', '0' ) ) {
			return $validation_error;
		}

		$result = $this->verify_token( 'login' );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_error ) ) {
				$validation_error = new WP_Error();
			}
			$validation_error->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_error;
	}

	/**
	 * Validate registration request.
	 *
	 * @param WP_Error $validation_errors Current validation errors.
	 * @param string   $username          Submitted username.
	 * @param string   $email             Submitted email.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_registration( $validation_errors, $username, $email ) {
		if ( '1' !== get_option( 'recaptcha_woo_enable_registration', '0' ) ) {
			return $validation_errors;
		}

		$result = $this->verify_token( 'registration' );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_errors ) ) {
				$validation_errors = new WP_Error();
			}
			$validation_errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_errors;
	}

	/**
	 * Validate checkout request.
	 *
	 * @param array    $data   Post data.
	 * @param WP_Error $errors Validation errors object.
	 */
	public function validate_checkout( $data, $errors ) {
		if ( '1' !== get_option( 'recaptcha_woo_enable_checkout', '0' ) ) {
			return;
		}

		$result = $this->verify_token( 'checkout' );
		if ( is_wp_error( $result ) ) {
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}
	}

	/**
	 * Perform reCAPTCHA v3 siteverify call.
	 *
	 * @param string $context Target page context ('login', 'registration', 'checkout').
	 * @return true|WP_Error Returns true on success, WP_Error object on failure.
	 */
	private function verify_token( $context ) {
		$secret_key = get_option( 'recaptcha_woo_secret_key', '' );
		if ( empty( $secret_key ) ) {
			// Skip verification if credentials are not configured to avoid blocking users.
			return true;
		}

		$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';

		if ( empty( $token ) ) {
			return new WP_Error(
				'recaptcha_missing',
				__( '<strong>Error:</strong> Anti-spam verification token is missing. Please refresh the page and try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		// Determine the score threshold.
		$threshold = 0.5;
		if ( 'login' === $context ) {
			$threshold = floatval( get_option( 'recaptcha_woo_threshold_login', '0.5' ) );
		} elseif ( 'registration' === $context ) {
			$threshold = floatval( get_option( 'recaptcha_woo_threshold_registration', '0.5' ) );
		} elseif ( 'checkout' === $context ) {
			$threshold = floatval( get_option( 'recaptcha_woo_threshold_checkout', '0.5' ) );
		}

		// Build request parameters.
		$remote_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		$api_url = 'https://www.google.com/recaptcha/api/siteverify';
		$args    = array(
			'body' => array(
				'secret'   => $secret_key,
				'response' => $token,
				'remoteip' => $remote_ip,
			),
		);

		$response = wp_remote_post( $api_url, $args );

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'recaptcha_api_failed',
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || ! isset( $data['success'] ) ) {
			return new WP_Error(
				'recaptcha_invalid_response',
				__( '<strong>Error:</strong> Invalid verification response. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		if ( ! $data['success'] ) {
			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		// Check v3 score threshold.
		$score = isset( $data['score'] ) ? floatval( $data['score'] ) : 0.0;
		if ( $score < $threshold ) {
			return new WP_Error(
				'recaptcha_low_score',
				__( '<strong>Error:</strong> Verification score too low. Submission rejected as potential spam.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		return true;
	}
}
