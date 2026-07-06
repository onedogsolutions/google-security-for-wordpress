<?php
/**
 * WooCommerce Blocks / Store API Checkout Integration
 *
 * The classic (shortcode) checkout renders a server-side form, so GSWP_Frontend
 * can inject a hidden reCAPTCHA field and GSWP_Verifier can score it on the
 * woocommerce_after_checkout_validation hook. The modern Checkout block submits
 * over the Store API instead: there is no server-rendered form to inject into,
 * no $_POST payload, and the classic validation hooks never fire — so a store
 * using the block would silently receive zero reCAPTCHA scoring and zero
 * Transaction defense.
 *
 * This class closes that gap. It registers a frontend JS integration (so the
 * block sends a fresh token in the checkout request's `extensions.gswp.token`)
 * and scores that token on the Store API checkout hook, reusing GSWP_Verifier.
 * The Transaction defense annotation layer is order-based and already fires for
 * block orders once the assessment name is written to order meta here.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Blocks {

	/**
	 * Store API extension namespace carrying our token.
	 */
	const EXT_NAMESPACE = 'gswp';

	/**
	 * Shared verifier used to score the token.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Constructor. Wires the block integration and Store API hooks. Inert unless
	 * WooCommerce Blocks is present, so it is a no-op on classic-only stores or
	 * very old WooCommerce versions.
	 *
	 * @param GSWP_Verifier $verifier Shared verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		// Register the frontend JS integration with the Checkout block.
		add_action( 'woocommerce_blocks_checkout_block_registration', array( $this, 'register_integration' ) );

		// Declare the extension schema so `extensions.gswp.token` is accepted on
		// the Store API checkout endpoint.
		add_action( 'woocommerce_blocks_loaded', array( $this, 'register_endpoint_data' ) );

		// Score the token as the Store API builds the order from the request.
		add_action( 'woocommerce_store_api_checkout_update_order_from_request', array( $this, 'validate_store_checkout' ), 10, 2 );
	}

	/**
	 * Register the IntegrationInterface implementation with the block registry.
	 *
	 * The interface class only exists once WooCommerce Blocks has loaded, which
	 * is guaranteed by the time this hook fires, so the integration class is
	 * required lazily here to keep the plugin parseable without Blocks.
	 *
	 * @param object $integration_registry The block integration registry.
	 */
	public function register_integration( $integration_registry ) {
		require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-blocks-integration.php';
		$integration_registry->register( new GSWP_Blocks_Integration() );
	}

	/**
	 * Register the checkout endpoint extension schema for our namespace.
	 *
	 * Declaring the schema lets `extensions.gswp.token` flow through the Store
	 * API checkout request in a typed, documented way.
	 */
	public function register_endpoint_data() {
		if ( ! function_exists( 'woocommerce_store_api_register_endpoint_data' ) ) {
			return;
		}

		// The CheckoutSchema identifier is the stable string 'checkout'; use the
		// class constant when available and fall back to the literal otherwise.
		$endpoint = class_exists( '\Automattic\WooCommerce\StoreApi\Schemas\V1\CheckoutSchema' )
			? \Automattic\WooCommerce\StoreApi\Schemas\V1\CheckoutSchema::IDENTIFIER
			: 'checkout';

		woocommerce_store_api_register_endpoint_data(
			array(
				'endpoint'        => $endpoint,
				'namespace'       => self::EXT_NAMESPACE,
				'schema_callback' => static function () {
					return array(
						'token' => array(
							'description' => __( 'reCAPTCHA token for the checkout submission.', 'google-security-for-wordpress' ),
							'type'        => 'string',
							'context'     => array(),
							'readonly'    => true,
						),
					);
				},
				'schema_type'     => ARRAY_A,
			)
		);
	}

	/**
	 * Score the block checkout token as the order is built from the request.
	 *
	 * Runs during the Store API checkout flow before payment. A verification
	 * failure (missing token, low score, invalid token) throws a RouteException,
	 * which aborts the checkout and surfaces the message in the block UI — the
	 * Store API equivalent of adding a WooCommerce checkout validation error.
	 *
	 * @param WC_Order        $order   Draft order being populated.
	 * @param WP_REST_Request $request Incoming Store API request.
	 *
	 * @throws \Automattic\WooCommerce\StoreApi\Exceptions\RouteException When
	 *         verification fails or the transaction is blocked as high risk.
	 */
	public function validate_store_checkout( $order, $request ) {
		if ( '1' !== get_option( 'gswp_enable_checkout', '0' ) ) {
			return;
		}
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$token      = '';
		$extensions = isset( $request['extensions'] ) ? $request['extensions'] : array();
		if ( isset( $extensions[ self::EXT_NAMESPACE ]['token'] ) ) {
			$token = sanitize_text_field( $extensions[ self::EXT_NAMESPACE ]['token'] );
		}

		$result = $this->verifier->assess_checkout_token( $token, $order );

		if ( is_wp_error( $result ) ) {
			$this->fail( $result->get_error_code(), $result->get_error_message() );
		}

		// Capture the Transaction defense verdict (Enterprise only; null otherwise).
		$risk = $this->verifier->get_last_fraud_risk();

		// Optional, opt-in high-risk block. transactionRisk is a fraud
		// probability: closer to 1.0 is riskier, so block when it meets the
		// threshold. Do this before persisting so a blocked order stays clean.
		if ( null !== $risk && '1' === get_option( 'gswp_txn_block', '0' ) ) {
			$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );
			if ( $risk >= $threshold ) {
				$this->log( sprintf( 'Transaction defense blocked block checkout: risk %.2f >= threshold %.2f.', $risk, $threshold ) );
				$this->fail(
					'gswp_transaction_risk',
					__( '<strong>Error:</strong> This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' )
				);
			}
		}

		// Attach the assessment to the order so the annotation layer
		// (GSWP_Transaction_Defense, on woocommerce_order_status_changed) can
		// label the outcome later. Written directly on the order — no WC session
		// bounce is needed because we already hold the order here.
		$name = $this->verifier->get_last_assessment_name();
		if ( '' !== $name ) {
			$order->update_meta_data( GSWP_Transaction_Defense::META_ASSESSMENT, $name );

			if ( null !== $risk ) {
				$order->add_order_note(
					sprintf(
						/* translators: %s: transaction risk score between 0 and 1. */
						__( 'reCAPTCHA Transaction defense risk score: %s', 'google-security-for-wordpress' ),
						number_format_i18n( $risk, 2 )
					)
				);
			}

			$order->save();
		}
	}

	/**
	 * Abort the Store API checkout with a customer-facing error.
	 *
	 * @param string $code    Error code.
	 * @param string $message Error message (HTML is stripped for the API).
	 *
	 * @throws \Automattic\WooCommerce\StoreApi\Exceptions\RouteException Always.
	 */
	private function fail( $code, $message ) {
		$prefixed = 0 === strpos( $code, 'gswp_' ) ? $code : 'gswp_' . $code;

		throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
			$prefixed,
			wp_strip_all_tags( $message ),
			400
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
