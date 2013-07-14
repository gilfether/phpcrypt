<?php
/**
 * An example of how to encrypt a file using AES-128 and CFB mode
 *
 */

error_reporting (E_ALL | E_STRICT);

include(dirname(__FILE__)."/../phpCrypt.php");
use PHP_Crypt\PHP_Crypt as PHP_Crypt;

$key = "^mY@TEst~Key_012";

$crypt = new PHP_Crypt($key, PHP_Crypt::CIPHER_AES_128, PHP_Crypt::MODE_CFB);
$encrypt = "";
$decrypt = "";
$result = "";

// CFB mode requires an IV, create it
$iv = $crypt->createIV();

// ENCRYPT file.txt
$rhandle = fopen("file.txt", "r");
$whandle = fopen("file.encrypted.txt", "w+b");

while (!feof($rhandle))
{
	$byte = fread($rhandle, 1);
	$result = $crypt->encrypt($byte, $iv);
	fwrite($whandle, $result);
}
fclose($rhandle);
fclose($whandle);

// DECRYPT file.txt
$rhandle = fopen("file.encrypted.txt", "rb");
$whandle = fopen("file.decrypted.txt", "w+");

while (!feof($rhandle))
{
	$byte = fread($rhandle, 1);
	$result = $crypt->decrypt($byte, $iv);
	fwrite($whandle, $result);
}
fclose($rhandle);
fclose($whandle);

print "CIPHER: ".$crypt->cipherName()."\n";
print "MODE: ".$crypt->modeName()."\n";

?>