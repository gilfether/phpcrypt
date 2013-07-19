<?php
/**
 * An example of how to encrypt a file using AES-128 and CFB mode
 *
 */

error_reporting (E_ALL | E_STRICT);

include(dirname(__FILE__)."/../phpCrypt.php");
use PHP_Crypt\PHP_Crypt as PHP_Crypt;

$key = "^mY@TEst~Key_012";

$crypt = new PHP_Crypt($key, PHP_Crypt::CIPHER_AES_128, PHP_Crypt::MODE_NCFB);
$cipher_block_sz = $crypt->cipherBlockSize() / 8;
$encrypt = "";
$decrypt = "";
$result = "";


print "Encrypting file.txt using:\n";
print "CIPHER: ".$crypt->cipherName()."\n";
print "MODE: ".$crypt->modeName()."\n";


/*
 * DO THE ENCRYPTION
 */
$rhandle = fopen("file.txt", "r");
$whandle = fopen("file.encrypted.txt", "w+b");
print "Creating file.encrypted.txt\n";

// CFB mode requires an IV, create it
$iv = $crypt->createIV();

while (!feof($rhandle))
{
	$byte = fread($rhandle, $cipher_block_sz);
	$result = $crypt->encrypt($byte);
	fwrite($whandle, $result);
}
fclose($rhandle);
fclose($whandle);


/*
 * DO THE DECRYPTION
 */
$rhandle = fopen("file.encrypted.txt", "rb");
$whandle = fopen("file.decrypted.txt", "w+");
print "Creating file.decrypted.txt\n";

// we need to set the IV to the same IV used for encryption
$crypt->setIV($iv);

while (!feof($rhandle))
{
	$byte = fread($rhandle, $cipher_block_sz);
	$result = $crypt->decrypt($byte);
	fwrite($whandle, $result);
}
fclose($rhandle);
fclose($whandle);

print "Finished.\n";
?>