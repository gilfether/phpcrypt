<?php
/*
 * Author: Ryan Gilfether
 * URL: http://www.gilfether.com/phpCrypt
 * Date: March 30, 2013
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

namespace PHP_Crypt;
require_once(dirname(__FILE__)."/../Cipher.php");
require_once(dirname(__FILE__)."/../Mode.php");
require_once(dirname(__FILE__)."/../phpCrypt.php");


/**
 * Implements Counter (CTR) block cipher mode
 *
 * @author Ryan Gilfether
 * @link http://www.gilfether.com/phpcrypt
 * @copyright 2013 Ryan Gilfether
 */
class Mode_CTR extends Mode
{
	private $counter_pos = 0;

	/**
	 * Constructor
	 * Sets the cipher object that will be used for encryption
	 *
	 * @param object $cipher one of the phpCrypt encryption cipher objects
	 * @return void
	 */
	function __construct($cipher)
	{
		parent::__construct(PHP_CRYPT::MODE_CTR, $cipher);

		// set the block size, in bits
		$this->blockSize($cipher->bitSize() / 8);

		// this works with only block Ciphers
		if($cipher->type() != Cipher::BLOCK)
			trigger_error("CTR mode requires a block cipher", E_USER_WARNING);
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
	 * Encrypts an encrypted string
	 *
	 * @param string $text the string to be encrypted in CBC mode
	 * @return boolean Returns true
	 */
	public function encrypt(&$text)
	{
		$len = strlen($text);
		$blocksz = $this->blockSize();

		$max1 = $len / $blocksz;
		for($i = 0; $i < $max1; ++$i)
		{
			// get the current position in $text
			$pos = $i * $blocksz;

			// make sure we don't extend past the length of $text
			$byte_len = $blocksz;
			if(($pos + $byte_len) > $len)
				$byte_len = ($pos + $byte_len) - $len;

			// encrypt the register
			$this->enc_register = $this->register;
			$this->cipher->encrypt($this->enc_register);

			// grab a block of plain text and a block of encrypted register
			$block = substr($text, $pos, $byte_len);

			// xor the block
			$max2 = strlen($block);
			for($j = 0; $j < $max2; ++$j)
				$block[$j] = $block[$j] ^ $this->enc_register[$j];

			// replace the plain text block with the encrypted block
			$text = substr_replace($text, $block, $pos, $byte_len);

			// increment the counter and append it to register
			$this->counter();
		}

		return true;
	}


	/**
	 * Decrypt an encrypted string
	 *
	 * @param string $text The string to be decrypted in ECB mode
	 * @return boolean Returns true
	 */
	public function decrypt(&$text)
	{
		$len = strlen($text);
		$blocksz = $this->blockSize();

		$max1 = $len / $blocksz;
		for($i = 0; $i < $max1; ++$i)
		{
			// get the current position in $text
			$pos = $i * $blocksz;

			// make sure we don't extend past the length of $text
			$byte_len = $blocksz;
			if(($pos + $byte_len) > $len)
				$byte_len = ($pos + $byte_len) - $len;

			// encrypt the register
			$this->enc_register = $this->register;
			$this->cipher->encrypt($this->enc_register);

			// grab a block of plain text
			$block = substr($text, $pos, $byte_len);

			// xor the block with the register (which contains the IV)
			$max2 = strlen($block);
			for($j = 0; $j < $max2; ++$j)
				$block[$j] = $block[$j] ^ $this->enc_register[$j];

			// replace the encrypted block with the plain text
			$text = substr_replace($text, $block, $pos, $byte_len);

			// increment the counter and append it to register
			$this->counter();
		}

		return true;
	}


	/**
	 * This mode requires an IV
	 *
	 * @return boolean True
	 */
	public function requiresIV()
	{
		return true;
	}


	/**
	 * We initialization of the counter each time the IV is set
	 * so this function over rides Mode::createIV() to do this
	 *
	 * @param string $iv The IV to use if given, otherwise we create one
	 * @param string $src The source to create the IV from,
	 * 		see Mode::createIV() for options
	 * @return string The new IV
	 */
	public function createIV($src = null)
	{
		$iv = parent::createIV($src);

		// initialize the counter position to the right most byte
		$this->counter_pos = strlen($this->register) - 1;

		return $iv;
	}


	/**
	 * Increments the counter ($this->register), starting at the right most byte, and
	 * incrementing the byte by one. If the byte reaches 0xff, then we move the counter
	 * left one byte, incrementing it until it reaches 0xff, so on and so forth until we
	 * are either done encrypting/decrypting, or all bytes reach 0xff. If the latter happens
	 * the register will remain the same until encryption/decryption is completed
	 *
	 * @return void
	 */
	private function counter()
	{
		// if the counter has reached the beginning of the register, and all bytes are 0xff,
		// at this point we can either keep the register as a string with all
		// bytes 0xff, or we can move $this->counter_pos to the end of the string and start
		// start incrementing bytes again. I'll choose to do the latter, as at least it
		// provides a little more security than just reusing a string of all 0xff
		if($this->counter_pos == 0 && ord($this->register[$this->counter_pos]) == 0xff)
			$this->counter_pos = strlen($this->register) - 1;

		// increment the character by one
		$c = chr(ord($this->register[$this->counter_pos]) + 1);

		// if the character is equal to 0xff (255), we need to move one position
		// in the register
		if(ord($c) == 0xff)
		{
			// set the position to 0xff
			$this->register[$this->counter_pos] = $c;

			// move left one byte
			--$this->counter_pos;

			// increment the byte
			$c = chr(ord($this->register[$this->counter_pos]) + 1);
		}

		// set the byte in the register
		$this->register[$this->counter_pos] = $c;
	}
}
?>