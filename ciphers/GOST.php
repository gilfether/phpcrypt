<?php
/*
 * Author: Ryan Gilfether
 * URL: http://www.gilfether.com/phpCrypt
 * Date: Sep 21, 2013
 * Copyright (C) 2013 Ryan Gilfether
 *
 * This file is part of phpCrypt
 *
 * phpCrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

namespace PHP_CRYPT;
require_once(dirname(__FILE__)."/../Cipher.php");
require_once(dirname(__FILE__)."/../phpCrypt.php");


/**
 * Implements GOST Encryption
 * Note that since the GOST standard does not specify the
 * values for the 8 sboxes, not all GOST implementations
 * are the same. I am using the the sboxes used in the book
 * Applied Cryptography by Bruce Schneier, which is also
 * the values used by mCrypt, keeping this mCrypt compatible.
 *
 * Resources used to implement this algorithm:
 * Applied Cryptography by Bruce Schneier's (pages 331-334)
 *
 * @author Ryan Gilfether
 * @link http://www.gilfether.com/phpcrypt
 * @copyright 2013 Ryan Gilfether
 */
class Cipher_GOST extends Cipher
{
	/** @type integer BYTES_BLOCK The block size, in bytes */
	const BYTES_BLOCK = 8; // 64 bits

	/** @type integer BYTES_KEY The key size, in bytes */
	const BYTES_KEY = 32; // 256 bits

	/** @type array $sub_keys The permutated subkeys */
	protected $sub_keys = array();

	/*
	 * THE SBOXES
	 * The standard does not specify the contents of the substitution
	 * boxes, saying they're a parameter of the network being set up.
	 * These are NOT the original s-boxes. I am using the ones from
	 * Bruce Schneier's book Applied Cryptography (pages 331-334),
	 * which are also the ones used by mCrypt
	 */

	/** @type array $_sbox1 Substitution Box 1 */
	private static $_sbox1 = array(
		4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3
	);

	/** @type array $_sbox1 Substitution Box 2 */
	private static $_sbox2 = array(
		14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9
	);

	/** @type array $_sbox1 Substitution Box 3 */
	private static $_sbox3 = array(
		5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11
	);

	/** @type array $_sbox1 Substitution Box 4 */
	private static $_sbox4 = array(
		7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3
	);

	/** @type array $_sbox1 Substitution Box 5 */
	private static $_sbox5 = array(
		6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2
	);

	/** @type array $_sbox1 Substitution Box 6 */
	private static $_sbox6 = array(
		4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14
	);

	/** @type array $_sbox1 Substitution Box 7 */
	private static $_sbox7 = array(
		13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12
	);

	/** @type array $_sbox1 Substitution Box 8 */
	private static $_sbox8 = array(
		1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 2
	);


	/**
	 * Constructor
	 *
	 * @param string $key The key used for Encryption/Decryption
	 * @return void
	 */
	public function __construct($key)
	{
		// set the key
		parent::__construct(PHP_Crypt::CIPHER_GOST, $key, self::BYTES_KEY);

		// initialize variables
		$this->initTables();

		// DES requires that data is 64 bits
		$this->blockSize(self::BYTES_BLOCK);

		// create the 16 rounds of 56 bit keys
		//$this->keyPermutation();
	}


	/**
	 * Destructor
	 *
	 * @return void
	 */
	public function __destruct()
	{
		parent::__destruct();
	}


	/**
	 * Encrypt plain text data using DES
	 *
	 * @param string $data A plain text string
	 * @return boolean Returns true
	 */
	public function encrypt(&$text)
	{
		$this->operation(parent::ENCRYPT);
		return $this->gost($text);
	}


	/**
	 * Decrypt a DES encrypted string
	 *
	 * @param string $encrypted A DES encrypted string
	 * @return boolean Returns true
	 */
	public function decrypt(&$text)
	{
		$this->operation(parent::DECRYPT);
		return $this->gost($text);
	}


	/**
	 * This is where the actual encrypt/decryption takes place.
	 *
	 * @param string $data The string to be encrypted or decrypted
	 * @return boolean Returns true
	 */
	protected function gost(&$data)
	{

		return true;
	}


	/**
	 * Initialize all the tables, this function is called inside the constructor
	 *
	 * @return void
	 */
	private function initTables()
	{

	}


	/**
	 * Indicates this is a block cipher
	 *
	 * @return integer Returns Cipher::BLOCK
	 */
	public function type()
	{
		return parent::BLOCK;
	}
}
?>