# twofish-php
Twofish encryption/decryption implementation in php, ported from Niels Ferguson's C code (version 0.3 from 2002).

To use this library you should: 
- Call new Twofish() in your program.
- Use PrepareKey(...) to convert a key to internal form. 
- Use Encrypt(...) and Decrypt(...) to encrypt and decrypt data. 
- Alternatively you can use CFB128Encrypt(...) and CFB128Decrypt(...) to encrypt and decrypt data of variable length.

See example:
```php
$key = new Twofish_key;
$twofish->PrepareKey($pass, $key);

//$in = 'string';
$in = 'string1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$out = '';
$num = 0;
$twofish->CFB128Encrypt($key, $in, $out, $ivec, $num);

$in2 = $out;
$out2 = '';
$num2 = 0;
$twofish->CFB128Decrypt($key, $in2, $out2, $ivec, $num2);

if ($out2 != $in)
{
	die( 'CFB128 error' );
}
```
