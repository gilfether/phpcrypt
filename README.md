phpCrypt - A PHP Encryption Library
=====================================================

WHAT IS PHPCRYPT?
-----------------

phpCrypt is an encryption library written in PHP from scratch. It aims to
implement all major encryption ciphers, modes, and other tools used for
encryption and decryption. phpCrypt does not rely on mCrypt, other PHP
extentions, or PEAR libraries.

It currently support many popular encryption ciphers. In addition it
supports many popular modes of encryption. There are also tools to implement
the different padding schemes, as well as multiple methods of creating an
Initialization Vecotor (IV) for modes that require one.

phpCrypt is developed by Ryan Gilfether <http://www.gilfether.com/phpcrypt>

WHAT DOES IT WORK ON?
---------------------

phpCrypt version 0.x works with PHP 5.3 or later. It will run on any
32 or 64 bit operating system that has PHP available for it.

SUPPORTED ENCRYPTION CIPHERS & MODES
------------------------------------
The list of supported encryption ciphers and modes is continually growing, each
new version of phpCrypt will add new ciphers or modes. The current list of
supported ciphers and modes are listed below:

Ciphers:

  	AES, ARC4 (an RC4 alternative), Blowfish, DES, Triple DES, Enigma,
	One Time Pad, RC2, Rijndael, SimpleXOR, Skipjack, Vignere

Modes:

	CBC, CFB, CTR, ECB, NCFB, NOFB, OFB, PCBC, Stream (used for Stream Ciphers)

DOCUMENTATION
-------------

The phpCrypt website at http://www.gilfether.com/phpcrypt lists much of the
information you need to begin. The phpCrypt website lists all the constants
you need to select ciphers,	modes, padding, and IV methods. In addition,
phpCrypt comes with an `examples` directory which has sample code to help get
you started.

Using phpCrypt is easy to use. An example of encrypting a string using AES-128
with CTR mode is demonstrated below:

	<?php
	include("/path/to/phpcrypt/phpCrypt.php");
	use PHP_Crypt\PHP_Crypt as PHP_Crypt;

	$data = "This is my secret message.";
	$key  = "MySecretKey01234";
	$crypt = new PHP_Crypt($key, PHP_Crypt::CIPHER_AES_128, PHP_Crypt::MODE_CTR);

	$iv = $crypt->createIV();
	$encrypt = $crypt->encrypt($data);

	$crypt->IV($iv);
	$decrypt = $crypt->decrypt($encrypt);
	?>

GENERATING RANDOM NUMBERS ON WINDOWS
------------------------------------

By default phpCrypt will use the PHP mt_rand() random number function on Windows
to create an IV. You have the option to use the random number generator found in the
Microsoft CAPICOM SDK which is more secure.

Before this will work you must install the Microsoft CAPICOM SDK and enable the PHP
com_dotnet extension:

* Download CAPICOM from Microsoft at http://www.microsoft.com/en-us/download/details.aspx?id=25281
* Double click the MSI file you downloaded and follow the install directions
* Open a command prompt and register the DLL: `regsvr32 C:\Program Files\PATH TO\CAPICOM SDK\Lib\X86\capicom.dll`
* Now edit php.ini to enable the com_dotnet extension: `extension=php_com_dotnet.dll`
* If you are running PHP as an Apache module, restart Apache.

To use the Windows random number generator in CAPICOM you would call createIV() like so:

	$iv = $crypt->createIV(PHP_Crypt::IV_WIN_COM);

GPL STUFF
---------

This file is part of phpCrypt

phpCrypt is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Please read the GPL file included in this distribution for the full license.
