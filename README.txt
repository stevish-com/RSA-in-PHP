RSA-in-PHP
==========

RSA dual key encryiption in Pure PHP.

This script is distributed under the terms of the GNU General Public License (GPL)
See http://www.gnu.org/licenses/gpl.txt for license details

Please use, distribute, modify, rip-off, sell or destroy this script however you see fit
I only ask that you remove my copyright if you modify and re-release this.
To make sure you have the genuine, up-to-date version, visit ...

To use:
=======
$text = "Peter Piper picked a peck of pickled peppers";
$RSA = new RSA_Handler();
$keys = $RSA->generate_keypair(1024);
$encrypted = $RSA->encrypt($text, $keys[0]);
$decrypted = $RSA->decrypt($encrypted, $keys[1]);
echo $decrypted; //Will print Peter Piper picked a peck of pickled peppers

Changelog
=========
Version 2.1: The code is now more efficient, and uses number of bits to determine key sizes (instead of number of digits).

Version 2.0: I have updated the code! It is now 100% portable and full functioning. The only thing I have left out is the ability to encrypt the private key, but there are several pure PHP implementations of AES, DES3, Blowfish etc. which can be used to encrypt a private key for storage.

Version 1 (initial release): I didn’t really make these classes to be portable, so in the RSA_Handler class, there are a few things that I did my own way (mostly in the generate_keys and encrypt functions). For the most basic usage, use an RSA_keymaker object and the make_keys function. The function will return an array of keys (in number form) where $keys[0] is the public key, $keys[1] is the private key and $keys[2] is the modulo. The keys generated with the default function are around 1024 bits (a 310 digit modulo).

