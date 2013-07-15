<?php
/*
 * Author: Ryan Gilfether
 * URL: http://www.gilfether.com/phpCrypt
 * Date: Sep 4, 2005
 * Copyright (C) 2005 Ryan Gilfether
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


namespace PHP_Crypt;
require_once(dirname(__FILE__)."/Base.php");


/**
 * Generic parent class for ciphers. Should not be used directly,
 * instead a class should extend from this class
 *
 * @author Ryan Gilfether
 * @link http://www.gilfether.com/phpcrypt
 * @copyright 2005 Ryan Gilfether
 */
abstract class Cipher extends Base
{
	/** @type integer ENCRYPT Indicates when we are in encryption mode */
	const ENCRYPT = 1;

	/** @type integer DECRYPT Indicates when we are in decryption mode */
	const DECRYPT = 2;

	/** @type integer BLOCK Indicates that a cipher is a block cipher */
	const BLOCK = 1;

	/** @type integer STREAM Indicates that a cipher is a stream cipher */
	const STREAM = 2;

	/** @type string $key Stores the key for the Cipher */
	protected $key = "";

	/** @type string $cipher_name Stores the name of the cipher */
	protected $cipher_name = "";

	/** @type integer $bit_size The block size of the cipher in bits */
	protected $bit_size = 0;

	/**
	 * @type integer $operation Indicates if a cipher is Encrypting or Decrypting
	 * this can be set to either Cipher::ENCRYPT or Cipher::DECRYPT
	 */
	protected $operation = self::ENCRYPT; // can be either Cipher::ENCRYPT | Cipher::DECRYPT;

	/** @type integer $req_key_sz The required key size for a cipehr, in bits */
	private $req_key_sz = 0;

	/** @type integer $key_pos Used for keyChunk(), to determine the current position in the kye */
	private $key_pos = 0;


	/**
	 * Constructor
	 *
	 * @param string $cipher_name one of the predefined ciphers
	 * @param string $key The key used for encryption
	 * @param int Optional, the required size of a key for the cipher
	 * @return void
	 */
	protected function __construct($cipher_name, $key = "", $required_key_sz = 0)
	{
		$this->cipher_name = $cipher_name;
		$this->setKey($key, $required_key_sz);
	}


	/**
	 * Destructor
	 *
	 * @return void
	 */
	protected function __destruct()
	{

	}



	/**********************************************************************
	 * ABSTRACT METHODS
	 *
	 * The abstract methods required by inheriting classes to implement
	 **********************************************************************/

	/**
	 * The cipher's encryption function. Must be defined
	 * by the class inheriting this Cipher object. This function
	 * will most often be called from within the Mode object
	 *
	 * @param string $text The text to be encrypted
	 * @return boolean Always returns false
	 */
	abstract public function encrypt(&$text);


	/**
	 * The cipher's decryption function. Must be defined
	 * by the class inheriting this Cipher object. This function
	 * will most often be called from within the Mode object
	 *
	 * @param string $text The text to decrypt
	 * @return boolean Always returns false
	 */
	abstract public function decrypt(&$text);


	/**
	 * Indiciates whether the cipher is a block or stream cipher
	 *
	 * @return integer Returns either Cipher::BLOCK or Cipher::STREAM
	 */
	abstract public function type();




	/**********************************************************************
	 * PUBLIC METHODS
	 *
	 **********************************************************************/

	/**
	 * Determine if we are Encrypting or Decrypting
	 * Since some ciphers use the same algorithm to Encrypt or Decrypt but with only
	 * slight differences, we need a way to check if we are Encrypting or Decrypting
	 * An example is DES, which uses the same algorithm except that when Decrypting
	 * the sub_keys are reversed
	 *
	 * @param integer $op Sets the operation to Cipher::ENCRYPT or Cipher::DECRYPT
	 * @return integer The current operation, either Cipher::ENCRYPT or Cipher::DECRYPT
	 */
	public function operation($op = 0)
	{
		if($op == self::ENCRYPT || $op == self::DECRYPT)
			$this->operation = $op;

		return $this->operation;
	}


	/**
	 * Return the name of cipher that is currently being used
	 *
	 * @return string The cipher name
	 */
	public function name()
	{
		return $this->cipher_name;
	}


	/**
	 * Size of the data in Bits that get used during encryption
	 *
	 * @param integer $bits Number of bits each block of data is required by the cipher
	 * @return integer The number of bits each block of data required by the cipher
	 */
	public function bitSize($bits = 0)
	{
		if($bits > 0)
			$this->bit_size = $bits;

		return $this->bit_size;
	}


	/**
	 * Returns the size (in bits) required by the cipher.
	 *
	 * @return integer The number of bits the cipher requires the key to be
	 */
	public function keySize()
	{
		return $this->req_key_sz;
	}



	/**********************************************************************
	 * PROTECTED METHODS
	 *
	 **********************************************************************/

	/**
	 * Returns a substring of $this->key. The size of the substring is set in the
	 * parameter $size. Each call to this function returns a substring starting
	 * in the position where the last substring ended. Effectively it rotates
	 * through the key, when it reaches the end, it starts over at the
	 * beginning of the key and continues on. You can reset the current position
	 * by setting the parameter $reset=true, which will start the key back at the
	 * first byte of the $this->key string.
	 *
	 * @param integer $size The size of the substring to return, in bytes
	 * @param bool $reset If set to true, sets the position back to 0, the first
	 *	byte of the key string
	 * @return string The next substring of the key
	 */
	protected function keyNextSubstr($size = 1, $reset = false)
	{
		if($reset || $this->key_pos >= strlen($this->key))
			$this->key_pos = 0;

		$bytes = substr($this->key, $this->key_pos, $size);
		$len = strlen($bytes);
		if($len < $size)
		{
			$bytes .= substr($this->key, 0, $size - $len);
			$this->key_pos = $size - $len;
		}
		else
			$this->key_pos += $size;

		return $bytes;
	}



	/**********************************************************************
	 * PRIVATE METHODS
	 *
	 **********************************************************************/

	/**
	 * Set the cipher key used for encryption/decryption. This function
	 * may lengthen or shorten the key to meet the size requirements of
	 * the cipher.
	 *
	 * @param string $key A key for the cipher
	 * @param integer $required_bit_size The byte size required for the key
	 * @return string They key, which made have been modified to fit size
	 *	requirements
	 */
	private function setKey($key, $required_bit_size = 0)
	{
		$this->req_key_sz = $required_bit_size;

		if($required_bit_size > 0)
		{
			$keylen = strlen($key);
			$req_bytes = $required_bit_size / 8;

			if($keylen > $req_bytes)
				$key = substr($key, 0, $req_bytes);
			else if($keylen < $req_bytes)
			{
				$msg = strtoupper($this->name())." requires a $req_bytes byte key, $keylen bytes received.";
				trigger_error($msg, E_USER_WARNING);
			}
		}

		$this->key = $key;
		return $this->key;
	}
}
?>