<?php
/**
 * Transaction Defense Class
 *
 * Completes the reCAPTCHA Enterprise Transaction defense integration by tying
 * a checkout assessment to its WooCommerce order and annotating the outcome
 * (legitimate / fraudulent) so Google's fraud model keeps learning.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Transaction_Defense {

	/**
	 * Order meta key holding the assessment resource name.
	 */
	const META_ASSESSMENT = '_gswp_assessment_name';

	/**
	 * Order meta key flagging that the order has already been annotated.
	 */
	const META_ANNOTATED = '_gswp_annotated';

	/**
	 * Constructor. Wires the annotation hooks. Inert unless WooCommerce is
	 * active, an Enterprise key is configured, and the feature is enabled.
	 */
	public function __construct() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return;
		}
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return;
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return;
		}

		// Attach the assessment captured during checkout validation to the order.
		add_action( 'woocommerce_checkout_order_processed', array( $this, 'attach_assessment' ), 10, 1 );

		// Annotate the assessment as the order's outcome becomes known.
		add_action( 'woocommerce_order_status_changed', array( $this, 'maybe_annotate' ), 10, 4 );
	}

	/**
	 * Move the stashed assessment name from the session onto the new order.
	 *
	 * @param int $order_id The order being created.
	 */
	public function attach_assessment( $order_id ) {
		if ( ! WC()->session ) {
			return;
		}

		$name = WC()->session->get( 'gswp_assessment_name' );
		$risk = WC()->session->get( 'gswp_transaction_risk' );

		// Clear the session regardless so the value never bleeds into a later order.
		WC()->session->set( 'gswp_assessment_name', null );
		WC()->session->set( 'gswp_transaction_risk', null );

		if ( empty( $name ) ) {
			return;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			return;
		}

		$order->update_meta_data( self::META_ASSESSMENT, $name );

		if ( null !== $risk && '' !== $risk ) {
			$order->add_order_note(
				sprintf(
					/* translators: %s: transaction risk score between 0 and 1. */
					__( 'reCAPTCHA Transaction defense risk score: %s', 'google-security-for-wordpress' ),
					number_format_i18n( (float) $risk, 2 )
				)
			);
		}

		$order->save();
	}

	/**
	 * Annotate the assessment when an order reaches a terminal-ish status.
	 *
	 * @param int      $order_id   Order ID.
	 * @param string   $old_status Previous status (without wc- prefix).
	 * @param string   $new_status New status (without wc- prefix).
	 * @param WC_Order $order      Order object.
	 */
	public function maybe_annotate( $order_id, $old_status, $new_status, $order ) {
		$map = array(
			// A fulfilled order is a strong legitimate signal.
			'completed'  => array( 'LEGITIMATE', 'PAYMENT_GIVEN' ),
			'processing' => array( 'LEGITIMATE', 'PAYMENT_GIVEN' ),
			// Reversed or abandoned orders are treated as fraudulent signal.
			'refunded'   => array( 'FRAUDULENT', 'REFUND' ),
			'cancelled'  => array( 'FRAUDULENT', '' ),
			'failed'     => array( 'FRAUDULENT', '' ),
		);

		if ( ! isset( $map[ $new_status ] ) ) {
			return;
		}

		if ( ! $order instanceof WC_Order ) {
			$order = wc_get_order( $order_id );
		}
		if ( ! $order ) {
			return;
		}

		$name = $order->get_meta( self::META_ASSESSMENT );
		if ( empty( $name ) ) {
			return;
		}

		// Annotate each outcome once to avoid hammering the API on status churn.
		if ( $order->get_meta( self::META_ANNOTATED ) === $new_status ) {
			return;
		}

		list( $annotation, $event_type ) = $map[ $new_status ];

		$this->annotate( $name, $annotation, $event_type, $order );

		$order->update_meta_data( self::META_ANNOTATED, $new_status );
		$order->save();
	}

	/**
	 * Send an annotation for an assessment to the reCAPTCHA Enterprise API.
	 *
	 * Fails open: a network or configuration error is logged and ignored so an
	 * order's lifecycle is never blocked by the feedback call.
	 *
	 * @param string   $name       Assessment resource name (projects/…/assessments/…).
	 * @param string   $annotation LEGITIMATE or FRAUDULENT.
	 * @param string   $event_type Optional transactionEvent eventType, or ''.
	 * @param WC_Order $order      Order being annotated.
	 */
	private function annotate( $name, $annotation, $event_type, $order ) {
		$api_key = get_option( 'gswp_gcp_api_key', '' );
		if ( '' === $api_key || '' === $name ) {
			return;
		}

		$body = array( 'annotation' => $annotation );

		if ( '' !== $event_type ) {
			$body['transactionEvent'] = array(
				'eventType' => $event_type,
				'eventTime' => gmdate( 'Y-m-d\TH:i:s\Z' ),
			);
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
			$this->log( 'Transaction defense annotation failed to connect: ' . $response->get_error_message() );
			return;
		}

		$status = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $status ) {
			$detail = wp_remote_retrieve_body( $response );
			$this->log( 'Transaction defense annotation returned HTTP ' . $status . ' (' . $detail . ').' );
			return;
		}

		$order->add_order_note(
			sprintf(
				/* translators: %s: annotation label sent to Google (LEGITIMATE or FRAUDULENT). */
				__( 'reCAPTCHA Transaction defense annotated this order as %s.', 'google-security-for-wordpress' ),
				$annotation
			)
		);
	}

	/**
	 * Log a warning to the WooCommerce logger when available.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $message, array( 'source' => 'gswp' ) );
		}
	}
}
