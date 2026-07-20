<?php
/**
 * Scrypt Class
 *
 * Pure-PHP implementation of the scrypt key derivation function (RFC 7914),
 * used by the Password Defense feature to derive the username+password pair
 * hash Google's Password Check protocol requires.
 *
 * ext/sodium's scrypt (`sodium_crypto_pwhash_scryptsalsa208sha256`) cannot be
 * used here: it fixes the salt at 32 bytes and derives N/r/p internally from
 * opslimit/memlimit, while this protocol needs an arbitrary-length salt
 * (username bytes ‖ a constant) and the exact N=4096, r=8, p=1 parameters
 * Google's servers expect. PHP exposes no other scrypt implementation, so
 * this class implements RFC 7914 directly. The outer PBKDF2-HMAC-SHA256
 * legs use the native `hash_pbkdf2()`; only ROMix/BlockMix/Salsa20/8 (the
 * memory-hard core) run in PHP.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Scrypt {

	/**
	 * Derive a scrypt key.
	 *
	 * @param string $password Passphrase bytes.
	 * @param string $salt     Salt bytes.
	 * @param int    $n        CPU/memory cost, must be a power of two > 1.
	 * @param int    $r        Block size parameter.
	 * @param int    $p        Parallelization parameter.
	 * @param int    $len      Desired output length in bytes.
	 * @return string Derived key bytes.
	 */
	public static function hash( $password, $salt, $n, $r, $p, $len ) {
		$block_size = 128 * $r;

		$b = hash_pbkdf2( 'sha256', $password, $salt, 1, $block_size * $p, true );

		$blocks = array();
		for ( $i = 0; $i < $p; $i++ ) {
			$block    = substr( $b, $i * $block_size, $block_size );
			$blocks[] = self::romix( $block, $n, $r );
		}

		return hash_pbkdf2( 'sha256', $password, implode( '', $blocks ), 1, $len, true );
	}

	/**
	 * ROMix: the memory-hard core. Builds and then randomly re-reads a
	 * lookup table of N intermediate BlockMix states.
	 *
	 * @param string $block Input block, 128*r bytes.
	 * @param int    $n     Cost parameter.
	 * @param int    $r     Block size parameter.
	 * @return string Output block, 128*r bytes.
	 */
	private static function romix( $block, $n, $r ) {
		$x = $block;
		$v = array();

		for ( $i = 0; $i < $n; $i++ ) {
			$v[ $i ] = $x;
			$x       = self::blockmix( $x, $r );
		}

		for ( $i = 0; $i < $n; $i++ ) {
			$j = self::integerify( $x, $r ) % $n;
			$x = self::blockmix( self::xor_strings( $x, $v[ $j ] ), $r );
		}

		return $x;
	}

	/**
	 * Interpret the last 64-byte little-endian block of X as an integer mod N
	 * (only the low 32 bits ever matter since N is always far below 2^32).
	 *
	 * @param string $x 128*r-byte block.
	 * @param int    $r Block size parameter.
	 * @return int
	 */
	private static function integerify( $x, $r ) {
		$offset = ( 2 * $r - 1 ) * 64;
		$word   = substr( $x, $offset, 4 );
		$vals   = unpack( 'V', $word );
		return $vals[1];
	}

	/**
	 * BlockMix: mixes a 128*r-byte block through Salsa20/8, 64 bytes at a time.
	 *
	 * @param string $b Input block, 128*r bytes.
	 * @param int    $r Block size parameter.
	 * @return string Output block, 128*r bytes (even/odd-interleaved, per RFC).
	 */
	private static function blockmix( $b, $r ) {
		$chunks = str_split( $b, 64 );
		$x      = $chunks[ count( $chunks ) - 1 ];

		$out_even = array();
		$out_odd  = array();

		foreach ( $chunks as $i => $chunk ) {
			$x = self::salsa20_8( self::xor_strings( $x, $chunk ) );
			if ( 0 === $i % 2 ) {
				$out_even[] = $x;
			} else {
				$out_odd[] = $x;
			}
		}

		return implode( '', $out_even ) . implode( '', $out_odd );
	}

	/**
	 * The Salsa20/8 core hash function operating on a 64-byte block.
	 *
	 * @param string $block 64-byte input.
	 * @return string 64-byte output.
	 */
	private static function salsa20_8( $block ) {
		$in  = array_values( unpack( 'V16', $block ) );
		$x   = $in;

		for ( $i = 0; $i < 8; $i += 2 ) {
			$x[4]  ^= self::rotl( ( $x[0] + $x[12] ) & 0xFFFFFFFF, 7 );
			$x[8]  ^= self::rotl( ( $x[4] + $x[0] ) & 0xFFFFFFFF, 9 );
			$x[12] ^= self::rotl( ( $x[8] + $x[4] ) & 0xFFFFFFFF, 13 );
			$x[0]  ^= self::rotl( ( $x[12] + $x[8] ) & 0xFFFFFFFF, 18 );

			$x[9]  ^= self::rotl( ( $x[5] + $x[1] ) & 0xFFFFFFFF, 7 );
			$x[13] ^= self::rotl( ( $x[9] + $x[5] ) & 0xFFFFFFFF, 9 );
			$x[1]  ^= self::rotl( ( $x[13] + $x[9] ) & 0xFFFFFFFF, 13 );
			$x[5]  ^= self::rotl( ( $x[1] + $x[13] ) & 0xFFFFFFFF, 18 );

			$x[14] ^= self::rotl( ( $x[10] + $x[6] ) & 0xFFFFFFFF, 7 );
			$x[2]  ^= self::rotl( ( $x[14] + $x[10] ) & 0xFFFFFFFF, 9 );
			$x[6]  ^= self::rotl( ( $x[2] + $x[14] ) & 0xFFFFFFFF, 13 );
			$x[10] ^= self::rotl( ( $x[6] + $x[2] ) & 0xFFFFFFFF, 18 );

			$x[3]  ^= self::rotl( ( $x[15] + $x[11] ) & 0xFFFFFFFF, 7 );
			$x[7]  ^= self::rotl( ( $x[3] + $x[15] ) & 0xFFFFFFFF, 9 );
			$x[11] ^= self::rotl( ( $x[7] + $x[3] ) & 0xFFFFFFFF, 13 );
			$x[15] ^= self::rotl( ( $x[11] + $x[7] ) & 0xFFFFFFFF, 18 );

			$x[1]  ^= self::rotl( ( $x[0] + $x[3] ) & 0xFFFFFFFF, 7 );
			$x[2]  ^= self::rotl( ( $x[1] + $x[0] ) & 0xFFFFFFFF, 9 );
			$x[3]  ^= self::rotl( ( $x[2] + $x[1] ) & 0xFFFFFFFF, 13 );
			$x[0]  ^= self::rotl( ( $x[3] + $x[2] ) & 0xFFFFFFFF, 18 );

			$x[6]  ^= self::rotl( ( $x[5] + $x[4] ) & 0xFFFFFFFF, 7 );
			$x[7]  ^= self::rotl( ( $x[6] + $x[5] ) & 0xFFFFFFFF, 9 );
			$x[4]  ^= self::rotl( ( $x[7] + $x[6] ) & 0xFFFFFFFF, 13 );
			$x[5]  ^= self::rotl( ( $x[4] + $x[7] ) & 0xFFFFFFFF, 18 );

			$x[11] ^= self::rotl( ( $x[10] + $x[9] ) & 0xFFFFFFFF, 7 );
			$x[8]  ^= self::rotl( ( $x[11] + $x[10] ) & 0xFFFFFFFF, 9 );
			$x[9]  ^= self::rotl( ( $x[8] + $x[11] ) & 0xFFFFFFFF, 13 );
			$x[10] ^= self::rotl( ( $x[9] + $x[8] ) & 0xFFFFFFFF, 18 );

			$x[12] ^= self::rotl( ( $x[15] + $x[14] ) & 0xFFFFFFFF, 7 );
			$x[13] ^= self::rotl( ( $x[12] + $x[15] ) & 0xFFFFFFFF, 9 );
			$x[14] ^= self::rotl( ( $x[13] + $x[12] ) & 0xFFFFFFFF, 13 );
			$x[15] ^= self::rotl( ( $x[14] + $x[13] ) & 0xFFFFFFFF, 18 );
		}

		$out = '';
		for ( $i = 0; $i < 16; $i++ ) {
			$out .= pack( 'V', ( $x[ $i ] + $in[ $i ] ) & 0xFFFFFFFF );
		}
		return $out;
	}

	/**
	 * Rotate a 32-bit value left.
	 *
	 * @param int $v Value (already masked to 32 bits).
	 * @param int $n Rotation amount.
	 * @return int
	 */
	private static function rotl( $v, $n ) {
		return ( ( $v << $n ) | ( $v >> ( 32 - $n ) ) ) & 0xFFFFFFFF;
	}

	/**
	 * XOR two equal-length byte strings.
	 *
	 * @param string $a First string.
	 * @param string $b Second string.
	 * @return string
	 */
	private static function xor_strings( $a, $b ) {
		return $a ^ $b;
	}
}
