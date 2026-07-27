<?php
/**
 * Logging
 *
 * Every logging call in this plugin used to go straight to wc_get_logger(),
 * which does not exist without WooCommerce. On a site that takes payments
 * through Gravity Forms and has no WooCommerce installed — the configuration
 * this plugin now explicitly supports — those messages were written nowhere at
 * all. That is worst for exactly the messages that matter most: the coverage-gap
 * warning that says a form is being submitted unscored is designed to be loud,
 * and it was silent.
 *
 * This routes everything through one place that always records:
 *
 *  1. WooCommerce's logger when it is available, so existing installs keep the
 *     familiar "gswp" log source;
 *  2. the PHP error log — unconditionally for warnings and errors, not only
 *     under WP_DEBUG, because a security event is worth a line in the server
 *     log on any site;
 *  3. a short in-database tail, so the admin screen can show recent events on a
 *     site that has no log viewer of its own.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Log {

	/**
	 * Option holding the recent-events tail.
	 */
	const TAIL_OPTION = 'gswp_log_tail';

	/**
	 * How many entries the tail keeps.
	 */
	const TAIL_MAX = 50;

	/**
	 * Record an error: something is wrong and someone should look.
	 *
	 * @param string $message Log message.
	 */
	public static function error( $message ) {
		self::write( 'error', $message );
	}

	/**
	 * Record a warning: an anomaly, a fail-open, a skipped verification.
	 *
	 * @param string $message Log message.
	 */
	public static function warning( $message ) {
		self::write( 'warning', $message );
	}

	/**
	 * Record routine detail. Only written when verbose logging is enabled, and
	 * never added to the tail — the tail is for things worth noticing.
	 *
	 * @param string $message Log message.
	 */
	public static function info( $message ) {
		if ( '1' !== get_option( 'gswp_verbose_logging', '0' ) ) {
			return;
		}

		self::write( 'info', $message, false );
	}

	/**
	 * Write a message to every available sink.
	 *
	 * @param string $level   'error', 'warning' or 'info'.
	 * @param string $message Log message.
	 * @param bool   $tail    Whether to add it to the in-database tail.
	 */
	private static function write( $level, $message, $tail = true ) {
		$message = (string) $message;

		if ( function_exists( 'wc_get_logger' ) ) {
			$logger = wc_get_logger();
			if ( 'error' === $level ) {
				$logger->error( $message, array( 'source' => 'gswp' ) );
			} elseif ( 'warning' === $level ) {
				$logger->warning( $message, array( 'source' => 'gswp' ) );
			} else {
				$logger->info( $message, array( 'source' => 'gswp' ) );
			}
		} elseif ( 'info' !== $level || ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ) {
			// No WooCommerce: warnings and errors always reach the PHP error
			// log, routine detail only under WP_DEBUG.
			error_log( 'GSWP [' . $level . '] ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}

		if ( $tail ) {
			self::append_tail( $level, $message );
		}
	}

	/**
	 * Append to the recent-events tail.
	 *
	 * @param string $level   Severity.
	 * @param string $message Log message.
	 */
	private static function append_tail( $level, $message ) {
		$tail = get_option( self::TAIL_OPTION, array() );
		$tail = is_array( $tail ) ? $tail : array();

		$tail[] = array(
			'time'    => time(),
			'level'   => $level,
			'message' => $message,
		);

		if ( count( $tail ) > self::TAIL_MAX ) {
			$tail = array_slice( $tail, -self::TAIL_MAX );
		}

		update_option( self::TAIL_OPTION, $tail, false );
	}

	/**
	 * The recent-events tail, newest first.
	 *
	 * @param int $limit Maximum entries to return.
	 * @return array
	 */
	public static function tail( $limit = 25 ) {
		$tail = get_option( self::TAIL_OPTION, array() );
		$tail = is_array( $tail ) ? array_reverse( $tail ) : array();

		return array_slice( $tail, 0, max( 1, (int) $limit ) );
	}

	/**
	 * Empty the tail.
	 */
	public static function clear() {
		delete_option( self::TAIL_OPTION );
	}
}
