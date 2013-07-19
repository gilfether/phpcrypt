<?php
/*
 * Demonstrates how IV's are created using modes that require them. Not
 * all modes require an IV. IV's can be created in 3 ways:
 *
 * PHP_Crypt::IV_RAND - uses PHP's mt_rand() to generate an IV.
 * This is the only option available in Windows
 *
 * PHP_Crypt::IV_DEV_RAND - uses the Unix /dev/random random number generator.
 * More secure than PHP_Crypt::RAND. Not available in Windows.
 *
 * PHP_Crypt::IV_DEV_URAND - uses the Unix /dev/urandom random number generator.
 * More secure than PHP_Crypt::RAND. Not Available for Windows.
 *
 * In the case where an PHP_Crypt::createIV is created for a Mode that does not require it,
 * the function returns and does not create an IV.
 *
 * The same IV must be used to decrypt a message as was used to Encrypt it.
 */

error_reporting (E_ALL | E_STRICT);

include(dirname(__FILE__)."/../phpCrypt.php");
use PHP_Crypt\PHP_Crypt as PHP_Crypt;
use PHP_Crypt\Cipher as Cipher;

$text = "This is my secret message.";
$key = "^mY@TEst";

/**
 * Cipher: DES
 * Mode: EBC
 */

$crypt = new PHP_Crypt($key, PHP_Crypt::CIPHER_DES, PHP_Crypt::MODE_CFB);

// by default createIV() uses PHP_Crypt::IV_RAND which uses PHP's mt_rand()
$iv = $crypt->createIV();

/*
 * // WE COULD ALSO USE THE FOLLOWING WAYS OF CREATING AN IV.
 * $iv = $crypt->createIV(PHP_Crypt::IV_RAND);
 * $iv = $crypt->createIV(PHP_Crypt::IV_DEV_RAND);
 * $iv = $crypt->createIV(PHP_CRYPT::IV_DEV_URAND);
 *
 * In the case where you are given an encrypted string, along with the key, and IV
 * to decrypt the string, you don't need to call createIV() since the IV has already
 * been created for you. Set the IV by calling $crypt->setIV($iv) as shown below.
 */

$encrypt = $crypt->encrypt($text);

// we need to use the same IV for decryption as used during encryption
$crypt->IV($iv);
$decrypt = $crypt->decrypt($encrypt);

print "CIPHER: ".$crypt->cipherName()."\n";
print "MODE: ".$crypt->modeName()."\n";
print "PLAIN TEXT: $text\n";
print "PLAIN TEXT HEX: ".Cipher::string2Hex($text)."\n";
print "ENCRYPTED HEX: ".Cipher::string2Hex($encrypt)."\n";
print "DECRYPTED: $decrypt\n";
print "DECRYPTED HEX: ".Cipher::string2Hex($decrypt)."\n";
?>