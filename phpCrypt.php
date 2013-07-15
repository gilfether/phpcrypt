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

namespace php_crypt;
include_once(dirname(__FILE__)."/Includes.inc.php");

/**
 * The phpCrypt class, a front end to all the Ciphers and Modes phpCrypt supports
 *
 * @author Ryan Gilfether
 * @link http://www.gilfether.com/phpcrypt
 * @copyright 2005 Ryan Gilfether
 */
class PHP_Crypt
{
	// Ciphers
	const CIPHER_3DES			= "3des";
	const CIPHER_AES_128		= "aes-128";
	const CIPHER_AES_192		= "aes-192";
	const CIPHER_AES_256		= "aes-256";
	const CIPHER_ARC4			= "arc4"; // an alternative name to RC4, RC4 is trademarked
	const CIPHER_BLOWFISH		= "blowfish";
	const CIPHER_DES			= "des";
	const CIPHER_ENIGMA			= "enigma"; // historical & used for old unix crypt command
	const CIPHER_ONETIMEPAD		= "onetimepad";
	const CIPHER_RC2			= "rc2";
	const CIPHER_RIJNDAEL_128	= "rijndael-128";
	const CIPHER_RIJNDAEL_192	= "rijndael-192";
	const CIPHER_RIJNDAEL_256	= "rijndael-256";
	const CIPHER_SKIPJACK		= "skipjack";
	const CIPHER_SIMPLEXOR		= "simplexor";
	const CIPHER_VIGENERE		= "vigenere"; // historical

	// Modes
	const MODE_CBC	= "cbc";
	const MODE_CFB	= "cfb"; // 8 bit cfb mode
	const MODE_CTR	= "ctr";
	const MODE_ECB	= "ecb";
	const MODE_NCFB	= "ncfb"; // n-bit cfb mode
	const MODE_NOFB	= "nofb"; // n-bit ofb mode
	const MODE_OFB	= "ofb"; // 8 bit ofb mode
	const MODE_PCBC	= "pcbc";
	const MODE_RAW	= "raw";
	const MODE_STREAM = "stream";

	// IV sources for Modes
	const IV_RAND		= "rand"; // uses mt_rand(), windows & unix
	const IV_DEV_RAND	= "/dev/random";	// unix only
	const IV_DEV_URAND	= "/dev/urandom";	// unix only

	// Padding types
	const PAD_ZERO			= 0;
	const PAD_ANSI_X923		= 1;
	const PAD_ISO_10126		= 2;
	const PAD_PKCS7			= 3;
	const PAD_ISO_7816_4	= 4;


	/** @type object $cipher An instance of the cipher object selected */
	private $cipher = null;

	/** @type object $mode An instance of the mode object selected */
	private $mode = null;


	/**
	 * Constructor
	 *
	 * @param string $key The key to use for the selected Cipher
	 * @param string $cipher The type of cipher to use
	 * @param string $mode The encrypt mode to use with the cipher
	 * @return void
	 */
	public function __construct($key, $cipher = self::CIPHER_AES_128, $mode = self::MODE_ECB, $padding = self::PAD_ZERO)
	{
		/*
		 * CIPHERS
		 */
		switch($cipher)
		{
		case self::CIPHER_3DES:
			$this->cipher = new Cipher_3DES($key);
			break;

		case self::CIPHER_AES_128:
			$this->cipher = new Cipher_AES_128($key);
			break;

		case self::CIPHER_AES_192:
			$this->cipher = new Cipher_AES_192($key);
			break;

		case self::CIPHER_AES_256:
			$this->cipher = new Cipher_AES_256($key);
			break;

		case self::CIPHER_ARC4: // an alternative to RC4
			$this->cipher = new Cipher_ARC4($key);
			break;

		case self::CIPHER_BLOWFISH:
			$this->cipher = new Cipher_Blowfish($key);
			break;

		case self::CIPHER_DES:
			$this->cipher = new Cipher_DES($key);
			break;

		case self::CIPHER_ENIGMA:
			$this->cipher = new Cipher_Enigma($key);
			break;

		case self::CIPHER_ONETIMEPAD:
			$this->cipher = new Cipher_One_Time_Pad($key);
			break;

		case self::CIPHER_RC2:
			$this->cipher = new Cipher_RC2($key);
			break;

		case self::CIPHER_RIJNDAEL_128:
			$this->cipher = new Cipher_Rijndael_128($key);
			break;

		case self::CIPHER_RIJNDAEL_192:
			$this->cipher = new Cipher_Rijndael_192($key);
			break;

		case self::CIPHER_RIJNDAEL_256:
			$this->cipher = new Cipher_Rijndael_256($key);
			break;

		case self::CIPHER_SIMPLEXOR:
			$this->cipher = new Cipher_Simple_XOR($key);
			break;

		case self::CIPHER_SKIPJACK:
			$this->cipher = new Cipher_Skipjack($key);
			break;

		case self::CIPHER_VIGENERE:
			$this->cipher = new Cipher_Vigenere($key);
			break;

		default:
			trigger_error("$cipher is not a valid cipher", E_USER_WARNING);
		}


		/*
		 * MODES
		 */
		switch($mode)
		{
		case self::MODE_CBC:
			$this->mode = new Mode_CBC($this->cipher);
			break;

		case self::MODE_CFB:
			$this->mode = new Mode_CFB($this->cipher);
			break;

		case self::MODE_CTR:
			$this->mode = new Mode_CTR($this->cipher);
			break;

		case self::MODE_ECB:
			$this->mode = new Mode_ECB($this->cipher);
			break;

		case self::MODE_NCFB:
			$this->mode = new Mode_NCFB($this->cipher);
			break;

		case self::MODE_NOFB:
			$this->mode = new Mode_NOFB($this->cipher);
			break;

		case self::MODE_OFB:
			$this->mode = new Mode_OFB($this->cipher);
			break;

		case self::MODE_PCBC:
			$this->mode = new Mode_PCBC($this->cipher);
			break;

		case self::MODE_RAW:
			$this->mode = new Mode_RAW($this->cipher);
			break;

		case self::MODE_STREAM:
			$this->mode = new Mode_Stream($this->cipher);
			break;

		//case self::MODE_CTS:
		default:
			trigger_error("$mode is not a valid mode", E_USER_WARNING);
		}

		// set the default padding
		$this->setPadding($padding);
	}


	/**
	 * Destructor
	 *
	 * @return void
	 */
	public function __destruct()
	{

	}


	/**
	 * Encrypt a plain text message using the Mode and Cipher selected.
	 * Some stream modes require this function to be called in a loop
	 * which requires the use of $result parameter to retrieve
	 * the decrypted data.
	 *
	 * @param string $text The plain text string
	 * @return string The encrypted string
	 */
	public function encrypt($text, $iv = "")
	{
		if($iv != "")
			$this->setIV($iv);

		// check that an iv is set, if required by the mode
		$this->mode->checkIV();

		// the encryption is done inside the mode
		$this->mode->encrypt($text);
		return $text;
	}


	/**
	 * Decrypt an encrypted message using the Mode and Cipher selected.
	 * Some stream modes require this function to be called in a loop
	 * which requires the use of $result parameter to retrieve
	 * the decrypted data.
	 *
	 * @param string $text The encrypted string
	 * @return string The decrypted string
	 */
	public function decrypt($text, $iv = "")
	{
		if($iv != "")
			$this->setIV($iv);

		// check that an iv is set, if required by the mode
		$this->mode->checkIV();

		// the decryption is done inside the mode
		$this->mode->decrypt($text);
		return $text;
	}


	/**
	 * Return the cipher object being used
	 *
	 * @return object The Cipher object
	 */
	public function cipher()
	{
		return $this->cipher;
	}


	/**
	 * Return the mode object being used
	 *
	 * @return object The Mode object
	 */
	public function mode()
	{
		return $this->mode;
	}


	/**
	 * Return the Cipher Type used
	 *
	 * @return string The name of the cipher
	 */
	public function cipherName()
	{
		return $this->cipher->name();
	}


	/**
	 * Return the Mode Type used
	 *
	 * @return string The name of the mode
	 */
	public function modeName()
	{
		return $this->mode->name();
	}


	/**
	 * Returns Ciphers required block size in bits
	 *
	 * @return integer The cipher data block size, in bits
	 */
	public function cipherBlockSize()
	{
		return $this->cipher->bitSize();
	}


	/**
	 * Returns the cipher's required key size, in bits
	 *
	 * @return integer The cipher's key size requirement, in bits
	 */
	public function cipherKeySize()
	{
		return $this->cipher->keySize();
	}


	/**
	 * Creates an IV for the the Cipher selected, if one is required.
	 * If you already have an IV to use, this function does not need
	 * to be called, instead set it with setIV(). If you create an
	 * IV with createIV(), you do not need to set it with setIV(),
	 * as it is automatically set in this function
	 *
	 * $src values are:
	 * PHP_CRYPT::IV_RAND (default) - uses mt_rand
	 * PHP_CRYPT::IV_DEV_RAND - uses /dev/random
	 * PHP_CRYPT::IV_DEV_URAND - uses /dev/urandom
	 *
	 * @param string $src Optional, how the IV is generated, can be one of
	 *		PHP_CRYPT::IV_RAND, PHP_CRYPT::IV_DEV_RAND, PHP_CRYPT::IV_DEV_URAND
	 * @return string The IV that is being used by the mode
	 */
	public function createIV($src = self::IV_RAND)
	{
		return $this->mode->createIV("", $src);
	}


	/**
	 * Sets the IV to use. Note that you do not need to call
	 * this function if creating an IV using createIV(). This
	 * function is used when an IV has already been created
	 * outside of phpCrypt and needs to be set. Alternatively
	 * you can just pass the $iv parameter to the encrypt()
	 * or decrypt() functions
	 *
	 * @param string $iv The IV to use during Encryption/Decryption
	 * @return void
	 */
	public function setIV($iv)
	{
		$this->mode->createIV($iv);
	}


	/**
	 * Sets the type of padding to be used within the specified Mode
	 *
	 * @param string $type One of the predefined padding types
	 * @return void
	 */
	public function setPadding($type)
	{
		$this->mode->setPadding($type);
	}
}
?>