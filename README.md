 [![Build status](https://travis-ci.org/JavaCardSpot-dev/JCSWAlgs.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/JCSWAlgs)

:information_source: **IMPORTANT: This repository is used for class [PV204 Security Technologies at
Masaryk University](https://is.muni.cz/auth/predmety/predmet?lang=en;setlang=en;pvysl=3141746). All
meaningful improvements will be attempted to be pushed to upstream repository in June 2018.**

JCSWAlgs
========

The Suite of software reimplementations of selected cryptographic algorithms (primitives) potentially missing on your smartcard with JavaCard platform. Optimized for speed and small memory footprint.

Following algorithms are included at the moment:

From https://github.com/petrs/JCSWAlgs
-RSA-Optimal Asymmetric Encryption Padding (RSA-OAEP) , OAEP (EUROCRYPT-1994)

From https://github.com/albertocarp/Primitives_SmartCard
- AES (NIST,2001)
- TwineCipher (FSE2010)
- ZorroCipher (CHES2013)
- SHA-3Keccak  (NIST, 2015)
- SHA-512(SHA-2) (NIST, 2001)


All algorithms are allows to reuse already allocated cryptographic primitives and RAM memory arrays to decrease memory footprint. Allocation of the algorithm is therefore performed differently from native primitives (e.g., SWAES.getInstance() instead of Cipher.getInstance() is required).

Following Applets and APDU clients shows example usage of various primitives:

CipherApplet.java and SimpleAPDU.java for Twine and Zorro

AESApplet.java and AESAPDU.java for JavaCardAES

AES_CBC_Applet.java and AES_CBCAPDU.java for example of AES implementation in CBC mode

Sha3Applet.java and Sha3APDU.java for example of various SHA-3 Keccak Modes

Sha512Applet.java and Sha512APDU.java for example of SHA512 usage

RSAOAEPApplet.java and RSAOAEPApdu.java for example of RSA-OAEP usage

All the applets are checked to be working on cards with JCOP 2.1.1.
(white cards on gemplus readers)

Usage of Block ciphers-
-----

Twine_80
-----
````java
// Allocate instance of TwineCipher 
TwineCipher m_twine = new TwineCipher(); //new object
TwineCipher m_twine = TwineCipher.getInstance(); //static object

//initialize instance with key
m_twine.init(Key initkey, byte mode) 
//initkey is a DESKey with type KeyBuilder.TYPE_DES and length KeyBuilder.LENGTH_DES3_2KEY
//mode is Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT
//only uses first 10bytes of the key from the available 16 bytes in initkey

//m_twine.init(Key key, byte mode, byte[] buf, short bOff, short bLen) throws an error since 
//this mode of init is not supported in this implementation

// Encrypt/Decrypt data
m_twine.doFinal(byte[] inBuff, short inOffset, short inLength,byte[] outBuff, short outOffset)
//m_twine.update(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws an error since
//this mode of init is not supported in this implementation


````
ZorroCipher
-----
````java
// Allocate instance of ZorroCipher 
ZorroCipher m_zorro = new ZorroCipher(); //new object
ZorroCipher m_zorro = ZorroCipher.getInstance(); //static object

//initialize instance with key
m_zorro.init(Key initkey, byte mode) 
//initkey is a DESKey with type KeyBuilder.TYPE_DES and length KeyBuilder.LENGTH_DES3_2KEY
//mode is Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT

//m_zorro.init(Key key, byte mode, byte[] buf, short bOff, short bLen) throws an error since 
//this mode of init is not supported in this implementation

// Encrypt/Decrypt data
m_zorro.doFinal(byte[] inBuff, short inOffset, short inLength,byte[] outBuff, short outOffset)
//m_zorro.update(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws an error since
//this mode of init is not supported in this implementation

````

AES Cipher
-----
````java
// Allocate instance of JavaCardAES 
JavaCardAES m_aes = new JavaCardAES(); //new object
JavaCardAES m_aes = JavaCardAES.getInstance(); //static object

//initialize instance with key
m_aes.init(Key initkey, byte mode) 
//initkey is a DESKey with type KeyBuilder.TYPE_DES and length KeyBuilder.LENGTH_DES3_2KEY
//mode is Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT

//m_aes.init(Key key, byte mode, byte[] buf, short bOff, short bLen) throws an error since 
//this mode of init is not supported in this implementation

// Encrypt/Decrypt data
m_aes.doFinal(byte[] inBuff, short inOffset, short inLength,byte[] outBuff, short outOffset)
//m_aes.update(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws an error since
//this mode of init is not supported in this implementation
````

SHA512(SHA2)
-----
````java
//init
Sha512.init()

//reset
Sha512.reset()

//update
Sha512.update(=inBuff, inOffset, inLength)

//final
Sha512.doFinal(inBuff, inOffset, inLength, outBuff,outOffset)

````
SHA3
-----
````java
Sha3Keccak cipherHash = Sha3Keccak.getInstance(HASH_ALG);
cipherHash.postInit();
len_data  = cipherHash.process(HASH, buf, bufOff, count_data);
//Hash_ALG = IConsts.HASH_KECCAK_160, IConsts.HASH_KECCAK_r144c256, IConsts.HASH_KECCAK_r128c272
//			 IConsts.HASH_KECCAK_r544c256,IConsts.HASH_KECCAK_r512c288, IConsts.HASH_KECCAK_r256c544,

````

RSA OAEP
-----
````java
// Allocate instance of RSA with OAEP 
// cipherEngine (Cipher), hashEngine (MessageDigest) and rngEngine (RandomData) are native JavaCard engines
RSAOAEP rsaOAEP = RSAOAEP.getInstance(cipherEngine, hashEngine, rngEngine, optEncParams, optAuxRAMArray);

// Encrypt data
rsaOAEP.init(m_rsaPubKey, Cipher.MODE_ENCRYPT);
short wrapLen = m_rsaOAEP.doFinal(inArray, baseOffset, dataLen, outArray, baseOffset);

// Decrypt data
rsaOAEP.init(m_rsaPrivKey, Cipher.MODE_DECRYPT);
unwrapLen = m_rsaOAEP.doFinal(inArray, baseOffset, wrapLen, outArray, baseOffset);
````


Based on gardle template available at https://github.com/crocs-muni/javacard-gradle-template-edu


[JCSWAlgs,Copyright (C) 2018,  Rao Arvind Mallari, Singh Ram, Singh Bhupendra & Svenda Petr.]
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under conditions covered by GPLv3.


