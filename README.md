 [![Build status](https://travis-ci.org/JavaCardSpot-dev/JCSWAlgs.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/JCSWAlgs)

:information_source: **IMPORTANT: This repository is used for class [PV204 Security Technologies at
Masaryk University](https://is.muni.cz/auth/predmety/predmet?lang=en;setlang=en;pvysl=3141746). All
meaningful improvements will be attempted to be pushed to upstream repository in June 2018.**

JCSWAlgs
========

The Suite of software reimplementations of selected cryptographic algorithms potentially missing on your smartcard with JavaCard platform. Optimized for speed and small memory footprint.

Following algorithms are included at the moment:

From https://github.com/petrs/JCSWAlgs
-RSA-Optimal Asymmetric Encryption Padding (RSA-OAEP) 

From https://github.com/albertocarp/Primitives_SmartCard
- AES
- TwineCipher (FSE2010)
- ZorroCipher (CHES2013)
- SHA3Keccak
- SHA-512


All algorithms are allows to reuse already allocated cryptographic primitives and RAM memory arrays to decrease memory footprint. Allocation of the algorithm is therefore performed differently from native primitives (e.g., SWAES.getInstance() instead of Cipher.getInstance() is required).


Usage - 
Twine_80
-----
````java
// Allocate instance of TwineCipher 
// m_dataArray is a 10byte buffer containing key
 m_TwineCipher = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80,m_dataArray);

// Encrypt data
len_data  = m_TwineCipher.process(OFFSET_P1_ENC, buf, bufOff, count_data);

// Decrypt data
len_data  = m_TwineCipher.process(TwineCipher.OFFSET_P1_DEC, buf,bufOff, count_data);

//set key (count_data should be 10bytes)
len_data = m_TwineCipher.process(TwineCipher.OFFSET_P1_GEN, buf, bufOff, count_data);

````
ZorroCipher
-----
````java
// Allocate instance of ZorroCipher 
 m_ZorroCipher = ZorroCipher.getInstance();

// Encrypt data
//count_data=32bytes, 1st 16bytes data, 2nd 16 bytes key
len_data  = m_ZorroCipher.process(OFFSET_P1_ENC, buf, bufOff, count_data);

// Decrypt data
//count_data=32bytes, 1st 16bytes data, 2nd 16 bytes key
len_data  = m_ZorroCipher process(TwineCipher.OFFSET_P1_DEC, buf,bufOff, count_data);

````

AES Cipher
-----
````java
// allocate engine
    JavaCardAES aesCipher = new JavaCardAES();
    // set array with initiualization vector
    aesCipher.m_IV = array_with_IV;
    aesCipher.m_IVOffset = 0;

    // schedule keys for first key into array array_for_round_keys_1
    aesCipher.RoundKeysSchedule(array_with_key1, (short) 0, array_for_round_keys_1);
    // encrypt block with first key
    aesCipher.AESEncryptBlock(data_to_encrypt, start_offset_of_data, array_for_round_keys_1);

    // schedule keys for second key into array array_for_round_keys_2
    aesCipher.RoundKeysSchedule(array_with_key_2, (short) 0, array_for_round_keys_2);
    // decrypt block with second key
    aesCipher.AESDecryptBlock(data_to_decrypt_2, start_offset_of_data, array_for_round_keys_2);

    // encrypt again with first key
    aesCipher.AESEncryptBlock(data_to_decrypt_2, start_offset_of_data, array_for_round_keys_1);
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


