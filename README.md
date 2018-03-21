 [![Build status](https://travis-ci.org/JavaCardSpot-dev/JCSWAlgs.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/JCSWAlgs)

:information_source: **IMPORTANT: This repository is used for class [PV204 Security Technologies at
Masaryk University](https://is.muni.cz/auth/predmety/predmet?lang=en;setlang=en;pvysl=3141746). All
meaningful improvements will be attempted to be pushed to upstream repository in June 2018.**

JCSWAlgs
========

The Suite of software reimplementations of selected cryptographic algorithms potentially missing on your smartcard with JavaCard platform. Optimized for speed and small memory footprint.

Following algorithms are included at the moment:

From https://github.com/petrs/JCSWAlgs
- Optimal Asymmetric Encryption Padding (OAEP) 

From https://github.com/albertocarp/Primitives_SmartCard
- TwineCipher
- AES
- SHA3Keccak
- SAH-2



All algorithms are allows to reuse already allocated cryptographic primitives and RAM memory arrays to decrease memory footprint. Allocation of the algorithm is therefore performed differently from native primitives (e.g., SWAES.getInstance() instead of Cipher.getInstance() is required).


Based on gardle template available at https://github.com/crocs-muni/javacard-gradle-template-edu


