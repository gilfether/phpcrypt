<?php
/*
 * Author: Ryan Gilfether
 * URL: http://www.gilfether.com/phpCrypt
 * Date: May 4, 2013
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
 * Implements a One Time Pad cipher
 * This implementation of the One Time Pad cipher is binary
 * safe. The strength of a One Time Pad relies on using a
 * truly random key, which is never reused. The key must
 * be the same length or longer than the message. A software generated
 * key is never truly random, and is not adequate to provide
 * security. Because of this it is not recommended you use this
 * for encrypting sensitive data. This is provided for 
 * informational purposes only, and because I was bored and felt
 * like implementing it.
 *
 * Resources used to implement this algorithm:
 * http://en.wikipedia.org/wiki/One-time_pad
 *
 * @author Ryan Gilfether
 * @link http://www.gilfether.com/phpcrypt
 * @copyright 2013 Ryan Gilfether
 */
class Cipher_One_Time_Pad extends Cipher
{
	/**
	 * Constructor
	 *
	 * @param string $key The key used for Encryption/Decryption
	 * @return void
	 */
	public function __construct($key)
	{
		// set the key
		parent::__construct(PHP_Crypt::CIPHER_ONETIMEPAD, $key);
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
	 * Encrypt plain text data using a One Time Pad
	 *
	 * @param string $data A plain text string
	 * @return boolean Returns true
	 */
	public function encrypt(&$text)
	{
		$this->operation(parent::ENCRYPT);
		$len = strlen($text);

		// if the key is too short, we can't continue
		if($len > strlen($this->key))
			trigger_error("The key length is shorter than the message length", E_USER_WARNING);

		for($i = 0; $i < $len; ++$i)
		{
			$val = ord($text[$i]) + ord($this->key[$i]);

			// if we reach past byte 255, subtract 255 to get a valid byte
			if($val > 255)
				$val = $val - 255;

			$text[$i] = chr($val);
		}

		return true;
	}


	/**
	 * Decrypt a One Time Pad encrypted string
	 *
	 * @param string $encrypted A One Time Pad encrypted string
	 * @return boolean Returns true
	 */
	public function decrypt(&$text)
	{
		$this->operation(parent::DECRYPT);
		$len = strlen($text);

		// if the key is too short, we can't continue
		if($len > strlen($this->key))
			trigger_error("The key length is shorter than the message length", E_USER_WARNING);

		for($i = 0; $i < $len; ++$i)
		{
			$val = ord($text[$i]) - ord($this->key[$i]);

			// if we are below byte 0, add 255 to get the original value
			if($val < 0)
				$val = $val + 255;

			$text[$i] = chr($val);
		}

		return true;
	}


	/**
	 * Indicates that this is a stream cipher
	 *
	 * @return integer Returns Cipher::STREAM
	 */
	public function type()
	{
		return parent::STREAM;
	}
}
?>