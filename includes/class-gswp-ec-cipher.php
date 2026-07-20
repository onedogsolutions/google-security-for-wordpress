<?php
/**
 * EC Commutative Cipher Class
 *
 * Implements the NIST P-256 commutative-encryption primitive Google's
 * Password Check protocol uses to blind the credentials hash: point
 * addition/doubling, scalar multiplication (double-and-add), point
 * compression/decompression, and the SHA-256 "random oracle" hash-to-curve
 * function from Google's `private-join-and-compute` `ECCommutativeCipher`
 * (Apache-2.0). This class is an independent implementation from the
 * publicly documented protocol and OpenSSL's `BN_mod_sqrt`/curve semantics —
 * no code is copied or translated from that project; it is used only as an
 * external test oracle during development (see PLAN §9).
 *
 * Arbitrary-precision arithmetic is required (P-256 field elements are
 * 256-bit) and PHP has no native bignum type, so this class needs GMP or
 * BCMath. GMP is used when available (much faster); BCMath is a fallback for
 * hosts without it. `GSWP_EC_Cipher::supported()` reports whether either is
 * present.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_EC_Cipher {

	/** NIST P-256 field prime, hex. */
	const P_HEX = 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF';

	/** NIST P-256 curve order, hex. */
	const N_HEX = 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';

	/** NIST P-256 curve coefficient b, hex. */
	const B_HEX = '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B';

	/** Which bignum backend is in use: 'gmp' or 'bcmath'. */
	private $backend;

	/** @var mixed Field prime p, in backend-native representation. */
	private $p;

	/** @var mixed Curve order n, in backend-native representation. */
	private $n;

	/** @var mixed Curve coefficient a = p - 3, in backend-native representation. */
	private $a;

	/** @var mixed Curve coefficient b, in backend-native representation. */
	private $b;

	/**
	 * Whether a usable bignum backend (GMP or BCMath) is present.
	 *
	 * @return bool
	 */
	public static function supported() {
		return PHP_INT_SIZE >= 8 && ( extension_loaded( 'gmp' ) || extension_loaded( 'bcmath' ) );
	}

	/**
	 * Constructor. Selects a backend and precomputes curve constants.
	 *
	 * @throws RuntimeException If neither GMP nor BCMath is available.
	 */
	public function __construct() {
		if ( extension_loaded( 'gmp' ) ) {
			$this->backend = 'gmp';
		} elseif ( extension_loaded( 'bcmath' ) ) {
			$this->backend = 'bcmath';
		} else {
			throw new RuntimeException( 'GSWP_EC_Cipher requires the GMP or BCMath PHP extension.' );
		}

		$this->p = $this->from_hex( self::P_HEX );
		$this->n = $this->from_hex( self::N_HEX );
		$this->b = $this->from_hex( self::B_HEX );
		$this->a = $this->sub( $this->p, $this->num( 3 ) ); // a = -3 mod p.
	}

	/* ---------------------------------------------------------------------
	 * Public protocol operations
	 * ------------------------------------------------------------------- */

	/**
	 * Hash an arbitrary byte string to a point on the curve, matching
	 * `ECCommutativeCipher::HashToTheCurve` (SHA256 variant): a "random
	 * oracle" candidate x-coordinate is derived from the message, and on
	 * each failure to find a valid y the candidate is re-hashed from its own
	 * bytes until a point is found.
	 *
	 * @param string $message Raw bytes to hash.
	 * @return array{0:mixed,1:mixed} Affine (x, y) coordinates.
	 */
	public function hash_to_curve( $message ) {
		$x = $this->random_oracle_sha256( $message );

		while ( true ) {
			$y2 = $this->y_squared( $x );
			if ( $this->is_square( $y2 ) ) {
				$y = $this->mod_sqrt( $y2 );
				if ( $this->is_odd( $y ) ) {
					$y = $this->sub( $this->p, $y );
				}
				return array( $x, $y );
			}
			$x = $this->random_oracle_sha256( $this->to_bytes( $x ) );
		}
	}

	/**
	 * Scalar-multiply a point: k * P (double-and-add). Used for both
	 * "encrypt" (our own key) and "decrypt" (our key's modular inverse mod n)
	 * — the caller passes whichever scalar is appropriate.
	 *
	 * @param mixed $k     Scalar, backend-native representation.
	 * @param array $point Affine (x, y) coordinates.
	 * @return array Affine (x, y) coordinates of k * point.
	 */
	public function scalar_mult( $k, $point ) {
		$result = null; // Point at infinity.
		$addend = $point;

		while ( $this->cmp( $k, $this->num( 0 ) ) > 0 ) {
			if ( $this->is_odd( $k ) ) {
				$result = $this->point_add( $result, $addend );
			}
			$addend = $this->point_add( $addend, $addend );
			$k      = $this->shr1( $k );
		}

		return $result;
	}

	/**
	 * Modular inverse of a scalar mod the curve order n (Fermat's little
	 * theorem: n is prime, so k^-1 = k^(n-2) mod n).
	 *
	 * @param mixed $k Scalar, backend-native representation.
	 * @return mixed
	 */
	public function invert_scalar( $k ) {
		return $this->powmod( $k, $this->sub( $this->n, $this->num( 2 ) ), $this->n );
	}

	/**
	 * SEC1 point compression: a single sign byte (0x02 even y / 0x03 odd y)
	 * followed by the 32-byte big-endian x-coordinate.
	 *
	 * @param array $point Affine (x, y) coordinates.
	 * @return string 33-byte compressed point.
	 */
	public function compress( $point ) {
		list( $x, $y ) = $point;
		$prefix = $this->is_odd( $y ) ? "\x03" : "\x02";
		return $prefix . $this->to_bytes_padded( $x, 32 );
	}

	/**
	 * Decompress a 33-byte SEC1 compressed point back to affine coordinates.
	 *
	 * @param string $data 33-byte compressed point.
	 * @return array Affine (x, y) coordinates.
	 * @throws InvalidArgumentException On malformed input.
	 */
	public function decompress( $data ) {
		if ( 33 !== strlen( $data ) ) {
			throw new InvalidArgumentException( 'Compressed point must be 33 bytes.' );
		}
		$prefix = ord( $data[0] );
		if ( 2 !== $prefix && 3 !== $prefix ) {
			throw new InvalidArgumentException( 'Invalid compressed point prefix.' );
		}
		$x  = $this->from_bytes( substr( $data, 1 ) );
		$y2 = $this->y_squared( $x );
		$y  = $this->mod_sqrt( $y2 );
		if ( $this->is_odd( $y ) !== ( 3 === $prefix ) ) {
			$y = $this->sub( $this->p, $y );
		}
		return array( $x, $y );
	}

	/**
	 * Random 32-byte scalar in [1, n-1] for use as a per-check ephemeral key.
	 *
	 * @return string Raw 32-byte big-endian scalar.
	 */
	public static function random_scalar_bytes() {
		do {
			$bytes = random_bytes( 32 );
		} while ( "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" === $bytes );
		return $bytes;
	}

	/**
	 * Parse raw big-endian scalar bytes into this backend's scalar
	 * representation, reduced mod n (a 32-byte random value is always < n's
	 * bit length but a defensive reduction costs nothing).
	 *
	 * @param string $bytes Raw big-endian scalar bytes.
	 * @return mixed
	 */
	public function scalar_from_bytes( $bytes ) {
		return $this->mod( $this->from_bytes( $bytes ), $this->n );
	}

	/* ---------------------------------------------------------------------
	 * Curve internals
	 * ------------------------------------------------------------------- */

	/**
	 * y^2 = x^3 + a*x + b (mod p).
	 *
	 * @param mixed $x
	 * @return mixed
	 */
	private function y_squared( $x ) {
		$x3 = $this->mulmod( $this->mulmod( $x, $x, $this->p ), $x, $this->p );
		$ax = $this->mulmod( $this->a, $x, $this->p );
		return $this->mod( $this->add( $this->add( $x3, $ax ), $this->b ), $this->p );
	}

	/**
	 * Euler's criterion: q is a nonzero quadratic residue mod p iff
	 * q^((p-1)/2) == 1. (Matches the reference's IsSquare, which also treats
	 * q = 0 as "not square" — an astronomically unlikely input here.)
	 *
	 * @param mixed $q
	 * @return bool
	 */
	private function is_square( $q ) {
		$exp = $this->div2( $this->sub( $this->p, $this->num( 1 ) ) );
		return 0 === $this->cmp( $this->powmod( $q, $exp, $this->p ), $this->num( 1 ) );
	}

	/**
	 * Modular square root for p = 3 (mod 4): sqrt = q^((p+1)/4) mod p.
	 * NIST P-256's prime satisfies this, so this closed form always applies.
	 *
	 * @param mixed $q
	 * @return mixed
	 */
	private function mod_sqrt( $q ) {
		$exp = $this->div2( $this->div2( $this->add( $this->p, $this->num( 1 ) ) ) );
		// (p+1)/4: p+1 is divisible by 4 for P-256 (p ≡ 3 mod 4), so two
		// successive exact halvings are equivalent and avoid a 4-divide helper.
		return $this->powmod( $q, $exp, $this->p );
	}

	/**
	 * Point addition/doubling in affine coordinates. `null` represents the
	 * point at infinity (identity element).
	 *
	 * @param array|null $p1
	 * @param array|null $p2
	 * @return array|null
	 */
	private function point_add( $p1, $p2 ) {
		if ( null === $p1 ) {
			return $p2;
		}
		if ( null === $p2 ) {
			return $p1;
		}

		list( $x1, $y1 ) = $p1;
		list( $x2, $y2 ) = $p2;

		if ( 0 === $this->cmp( $x1, $x2 ) ) {
			$sum = $this->mod( $this->add( $y1, $y2 ), $this->p );
			if ( 0 === $this->cmp( $sum, $this->num( 0 ) ) ) {
				return null; // P + (-P) = point at infinity.
			}
			// Doubling: lambda = (3*x1^2 + a) / (2*y1).
			$num    = $this->add( $this->mulmod( $this->num( 3 ), $this->mulmod( $x1, $x1, $this->p ), $this->p ), $this->a );
			$den    = $this->mulmod( $this->num( 2 ), $y1, $this->p );
			$lambda = $this->mulmod( $this->mod( $num, $this->p ), $this->invert( $den, $this->p ), $this->p );
		} else {
			// Distinct x: lambda = (y2 - y1) / (x2 - x1).
			$num    = $this->mod( $this->sub( $y2, $y1 ), $this->p );
			$den    = $this->mod( $this->sub( $x2, $x1 ), $this->p );
			$lambda = $this->mulmod( $num, $this->invert( $den, $this->p ), $this->p );
		}

		$x3 = $this->mod( $this->sub( $this->sub( $this->mulmod( $lambda, $lambda, $this->p ), $x1 ), $x2 ), $this->p );
		$y3 = $this->mod( $this->sub( $this->mulmod( $lambda, $this->mod( $this->sub( $x1, $x3 ), $this->p ), $this->p ), $y1 ), $this->p );

		return array( $x3, $y3 );
	}

	/**
	 * The `RandomOracleSha256(x, p)` construction from `private-join-and-compute`:
	 * two SHA-256 blocks, `SHA256(0x01‖x)` and `SHA256(0x02‖x)`, concatenated
	 * as a 512-bit big-endian integer and reduced mod p (p is 256 bits, so no
	 * excess-bit trimming is needed — output_bit_length == 2 * hash length).
	 *
	 * @param string $x Raw input bytes.
	 * @return mixed Candidate value mod p.
	 */
	private function random_oracle_sha256( $x ) {
		$h1 = hash( 'sha256', "\x01" . $x, true );
		$h2 = hash( 'sha256', "\x02" . $x, true );
		$combined = $this->from_bytes( $h1 . $h2 );
		return $this->mod( $combined, $this->p );
	}

	/* ---------------------------------------------------------------------
	 * Backend-dispatching bignum primitives (GMP or BCMath)
	 * ------------------------------------------------------------------- */

	private function num( $int ) {
		return 'gmp' === $this->backend ? gmp_init( $int ) : (string) $int;
	}

	private function from_hex( $hex ) {
		return 'gmp' === $this->backend ? gmp_init( $hex, 16 ) : self::bc_from_hex( $hex );
	}

	private function from_bytes( $bytes ) {
		if ( '' === $bytes ) {
			return $this->num( 0 );
		}
		return 'gmp' === $this->backend
			? gmp_import( $bytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN )
			: self::bc_from_hex( bin2hex( $bytes ) );
	}

	private function to_bytes( $value ) {
		if ( 0 === $this->cmp( $value, $this->num( 0 ) ) ) {
			return '';
		}
		return 'gmp' === $this->backend
			? gmp_export( $value, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN )
			: hex2bin( self::bc_pad_hex( self::bc_to_hex( $value ) ) );
	}

	private function to_bytes_padded( $value, $length ) {
		$bytes = $this->to_bytes( $value );
		$pad   = $length - strlen( $bytes );
		return $pad > 0 ? ( str_repeat( "\0", $pad ) . $bytes ) : $bytes;
	}

	private function add( $a, $b ) {
		return 'gmp' === $this->backend ? gmp_add( $a, $b ) : bcadd( $a, $b );
	}

	private function sub( $a, $b ) {
		return 'gmp' === $this->backend ? gmp_sub( $a, $b ) : bcsub( $a, $b );
	}

	private function mod( $a, $m ) {
		if ( 'gmp' === $this->backend ) {
			return gmp_mod( $a, $m );
		}
		// Unlike gmp_mod(), BCMath's bcmod() keeps the dividend's sign, so a
		// negative intermediate (routine in point arithmetic) must be folded
		// back into [0, m) by hand.
		$r = bcmod( $a, $m, 0 );
		return ( '-' === substr( $r, 0, 1 ) ) ? bcadd( $r, $m ) : $r;
	}

	private function mulmod( $a, $b, $m ) {
		if ( 'gmp' === $this->backend ) {
			return gmp_mod( gmp_mul( $a, $b ), $m );
		}
		return $this->mod( bcmul( $a, $b ), $m );
	}

	private function powmod( $base, $exp, $m ) {
		return 'gmp' === $this->backend ? gmp_powm( $base, $exp, $m ) : bcpowmod( $base, $exp, $m, 0 );
	}

	private function invert( $a, $m ) {
		if ( 'gmp' === $this->backend ) {
			return gmp_invert( $a, $m );
		}
		// BCMath has no modular inverse; m (= p, prime) lets Fermat's little
		// theorem stand in: a^-1 = a^(m-2) mod m.
		return bcpowmod( $a, bcsub( $m, '2' ), $m, 0 );
	}

	private function cmp( $a, $b ) {
		return 'gmp' === $this->backend ? gmp_cmp( $a, $b ) : bccomp( $a, $b, 0 );
	}

	private function is_odd( $value ) {
		if ( 'gmp' === $this->backend ) {
			return gmp_testbit( $value, 0 );
		}
		return '1' === bcmod( $value, '2', 0 );
	}

	private function shr1( $value ) {
		return 'gmp' === $this->backend ? gmp_div_q( $value, $this->num( 2 ) ) : bcdiv( $value, '2', 0 );
	}

	private function div2( $value ) {
		return $this->shr1( $value );
	}

	/**
	 * Convert a hex string to a BCMath decimal string.
	 *
	 * @param string $hex Hex digits (no 0x prefix).
	 * @return string Decimal string.
	 */
	private static function bc_from_hex( $hex ) {
		$hex    = ltrim( $hex, '0' );
		$result = '0';
		$len    = strlen( $hex );
		for ( $i = 0; $i < $len; $i++ ) {
			$result = bcadd( bcmul( $result, '16' ), (string) hexdec( $hex[ $i ] ) );
		}
		return $result;
	}

	/**
	 * Convert a BCMath decimal string to a (possibly odd-length, unpadded)
	 * hex string.
	 *
	 * @param string $dec Decimal string.
	 * @return string Hex digits.
	 */
	private static function bc_to_hex( $dec ) {
		if ( '0' === $dec ) {
			return '';
		}
		$hex = '';
		while ( bccomp( $dec, '0', 0 ) > 0 ) {
			$rem = bcmod( $dec, '16', 0 );
			$hex = dechex( (int) $rem ) . $hex;
			$dec = bcdiv( $dec, '16', 0 );
		}
		return $hex;
	}

	/**
	 * Left-pad a hex string to an even length so `hex2bin()` accepts it.
	 *
	 * @param string $hex Hex digits.
	 * @return string
	 */
	private static function bc_pad_hex( $hex ) {
		return ( strlen( $hex ) % 2 ) ? '0' . $hex : $hex;
	}
}
