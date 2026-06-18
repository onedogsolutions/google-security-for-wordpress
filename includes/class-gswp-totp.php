<?php
/**
 * TOTP Engine
 *
 * Self-contained implementation of time-based one-time passwords (RFC 6238) on
 * top of HMAC-based one-time passwords (RFC 4226), using Base32 secrets (RFC
 * 4648). This is the algorithm Google Authenticator, Authy, 1Password, and
 * Microsoft Authenticator all implement, so no external service or library is
 * required.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_TOTP {

	/**
	 * Time step in seconds. 30 is the de-facto standard authenticator apps use.
	 */
	const PERIOD = 30;

	/**
	 * Number of digits in a generated code.
	 */
	const DIGITS = 6;

	/**
	 * RFC 4648 Base32 alphabet.
	 */
	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new random Base32 secret.
	 *
	 * @param int $bytes Number of random bytes (20 = 160 bits, the SHA-1 block
	 *                   size recommended by RFC 4226).
	 * @return string Base32-encoded secret with no padding.
	 */
	public static function generate_secret( $bytes = 20 ) {
		return self::base32_encode( random_bytes( $bytes ) );
	}

	/**
	 * Encode raw bytes as Base32 (no padding).
	 *
	 * @param string $data Raw binary string.
	 * @return string Base32 string.
	 */
	public static function base32_encode( $data ) {
		if ( '' === $data ) {
			return '';
		}

		$buffer = 0;
		$bits   = 0;
		$out    = '';

		$len = strlen( $data );
		for ( $i = 0; $i < $len; $i++ ) {
			$buffer = ( $buffer << 8 ) | ord( $data[ $i ] );
			$bits  += 8;

			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::ALPHABET[ ( $buffer >> $bits ) & 0x1F ];
			}
		}

		if ( $bits > 0 ) {
			$out .= self::ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 0x1F ];
		}

		return $out;
	}

	/**
	 * Decode a Base32 string to raw bytes.
	 *
	 * @param string $b32 Base32 string (case-insensitive, padding optional).
	 * @return string|false Raw binary string, or false on invalid input.
	 */
	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( trim( $b32 ) );
		$b32 = rtrim( $b32, '=' );

		if ( '' === $b32 ) {
			return '';
		}

		$buffer = 0;
		$bits   = 0;
		$out    = '';

		$len = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$val = strpos( self::ALPHABET, $b32[ $i ] );
			if ( false === $val ) {
				return false;
			}

			$buffer = ( $buffer << 5 ) | $val;
			$bits  += 5;

			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $out;
	}

	/**
	 * Current time step counter.
	 *
	 * @param int|null $time Unix timestamp, or null for now.
	 * @return int Counter value.
	 */
	public static function timestep( $time = null ) {
		$time = ( null === $time ) ? time() : (int) $time;

		return (int) floor( $time / self::PERIOD );
	}

	/**
	 * Compute the code for a given secret and counter.
	 *
	 * @param string $secret  Base32 secret.
	 * @param int    $counter Time step counter.
	 * @return string|false Zero-padded numeric code, or false on invalid secret.
	 */
	public static function code_at( $secret, $counter ) {
		$key = self::base32_decode( $secret );
		if ( false === $key || '' === $key ) {
			return false;
		}

		// 8-byte big-endian counter. Two 32-bit words keep this correct on both
		// 32-bit and 64-bit PHP for counters below 2^32.
		$binary = pack( 'N*', 0, $counter );

		$hash   = hash_hmac( 'sha1', $binary, $key, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;

		$part = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		$otp = $part % ( 10 ** self::DIGITS );

		return str_pad( (string) $otp, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a submitted code against a secret.
	 *
	 * @param string   $secret         Base32 secret.
	 * @param string   $code           Submitted code.
	 * @param int      $window         Number of steps of clock drift to tolerate
	 *                                 on each side (1 = +/-30s).
	 * @param int|null $after_timestep Reject any counter at or below this value
	 *                                 to prevent replay of an already-used code.
	 * @return int|false The matched counter on success, false on failure.
	 */
	public static function verify( $secret, $code, $window = 1, $after_timestep = null ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$current = self::timestep();

		for ( $i = -$window; $i <= $window; $i++ ) {
			$counter = $current + $i;

			if ( null !== $after_timestep && $counter <= $after_timestep ) {
				continue;
			}

			$candidate = self::code_at( $secret, $counter );
			if ( false === $candidate ) {
				return false;
			}

			if ( hash_equals( $candidate, $code ) ) {
				return $counter;
			}
		}

		return false;
	}

	/**
	 * Build the otpauth:// provisioning URI for an authenticator app.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Account label (typically the username or email).
	 * @param string $issuer Issuer name (typically the site name).
	 * @return string otpauth:// URI.
	 */
	public static function provisioning_uri( $secret, $label, $issuer ) {
		$label = $issuer . ':' . $label;

		$query = http_build_query(
			array(
				'secret'    => $secret,
				'issuer'    => $issuer,
				'algorithm' => 'SHA1',
				'digits'    => self::DIGITS,
				'period'    => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);

		return 'otpauth://totp/' . rawurlencode( $label ) . '?' . $query;
	}
}
