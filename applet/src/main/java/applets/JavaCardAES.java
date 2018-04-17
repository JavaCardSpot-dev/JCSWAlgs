/*
Create by Petr Svenda http://www.svenda.com/petr

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Based on non-optimized example code for Rijndael by J. Daemon and V. Rijmen

USAGE:
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


APPLIED OPTIMIZATIONS:
- UNROLLED LOOPS (only minor effect as compiler is doing that also)
- PRE-COMPUTED Alogtable and Logtable (common)
- PRE-COMPUTED Alogtable_mul2 and Alogtable_mul3 (will speed-up MixColumn computation
   with 'mul((byte) 2, a[(short) (i + hlp)])' and 'mul((byte) 3, a[(short) (i + hlp)])' commands)
   * due to space-constraints, InvMixColumn is NOT optimized this way (separate tables for 0xe, 0xb, 0xd, 0x9 are needed)
   * note, on Cyberflex 32K e-gate there is time saving only 1 second from 9 sec to 8 sec (and tables needs 512B)
   * if have to be used, then uncomment parts  ALOG_MUL

SPEED (Cyberflex 32k e-gate):
- encryption (one block) on 9 second  (when MixColumn "removed", then only 4 sec => so you may try to optimize MixColumn)
- key schedule 4 seconds
- reduced version with 7 rounds only - 6 seconds (!! see note located above N_ROUNDS)

SPEED (GXP E64PK):
- encryption (one block) less than 1 second

/**/

package applets;
import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class JavaCardAES extends Cipher {
    public static final byte ALG_JCAES = 20;
    public static final byte LEBGTH_JCAES= 16;
    private DESKey cipherKey=null;
    /** Current mode. Possible values:
     * <code>Cipher.MODE_DECRYPT</code> or <code>Cipher.MODE_ENCRYPT</code>. */
    private byte mode;
    private boolean externalAccess;
    private boolean isInitialized = false;
    //ramarrays for roundkeys and IV
    private byte[] aesRoundKeys =null;
    private byte[] temp = null;


  final static short SW_IV_BAD                        = (short) 0x6709;   // BAD INICIALIZATION VECTOR
  final static short SW_CIPHER_DATA_LENGTH_BAD        = (short) 0x6710;   // BAD LENGTH OF DATA USED DURING CIPHER OPERATION

    // NOTE: BLOCKN is for block length  & KEYN is for key length CONSTANTS ARE DEFINED
    // ONLY FOR BETTER READIBILITY OF CODE AND CANNOT BE CHANGED!!!
    final public static byte BLOCKLEN                  = (byte) (128 / 8);
    final static byte BLOCKN    		= (byte) (128 / 32);
    final static byte KEYN    		        = (byte) (128 / 32);
    final static short STATELEN                 = (short) (4 * BLOCKN);

    // IMPORTANT: THIS IMPLEMENTATION IS CONSTRUCTED FOR 128bit KEY and 128bit BLOCK
    // FOR THIS SETTING, 10 ITERATION ROUNDS ARE GIVEN IN SPECIFICATION
    // HOWEVER, NUMBER OF THESE ROUNDS CAN BE DECREASED - CURRENTLY (2006) BEST KNOWN PRACTICALLY REALISABLE ATTACK
    // IS AGAINST REDUCED ALG. WITH 6 ROUNDS AND REQUIRE: 2^32 choosen plaintexts and 2^44 time steps (http://www.schneier.com/paper-rijndael.pdf)
    // THEREFORE 7 ROUNDS CANNOT BE ATTACKED RIGHT NOW (2006) ANF IF YOU *KNOW WHAT YOUR ARE DOING*,
    // THEN REDUCE ROUNDS AND GET 30% SPEED-UP
    // NOTE THAT ALGORITHM WILL NOT BE BINARY COMPATIBLE WITH AES TEST VECTORS ANYMORE
    public static byte N_ROUNDS    		= (byte) 10; // number of round is 10 as per AES standard

    //final static byte rcon[] = {(byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1b, (byte) 0x36};

     final static byte rcon[] = {(byte) 0xaa, (byte) 0xab, (byte) 0xac, (byte) 0xad, (byte) 0xae, (byte) 0xaf, (byte) 0xba, (byte) 0xbb, (byte) 0xbc, (byte) 0xbd};

    // shifts[0..3] -> ENCRYPT, shifts[4..7] ... DECRYPT
    final static byte shifts[] = { 0, 1, 2, 3, 0, 3, 2, 1};

    // NOTE: NEXT ARRAYS COULD BE DECLARED STATIC, BUT UNKNOWN PROBLEM OCCURES
    // DURING APPLET INSTALATION ON Gemplus GXPPro-R3.
    private byte SBox[] = null;
    private byte SiBox[] = null;
    private byte Alogtable[] = null;

    private short Logtable[] = null;

    // PREALOCATED REUSED TRANSIENT BUFFER
    private byte tempBuffer[] = null;

    // INICIALIZATION VECTOR
    private byte       m_IV[] = null;
    private short      m_IVOffset = 0;

    protected JavaCardAES() {
      // ALLOCATE AND COMPUTE LOOKUP TABLES
      SBox = new byte[256];
      SiBox = new byte[256];
      Alogtable = new byte[256];


      Logtable = new short[256];
      tempBuffer = JCSystem.makeTransientByteArray(STATELEN, JCSystem.CLEAR_ON_RESET);
      temp= JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
      m_IV = new byte[16];
      m_IVOffset=0;
      aesRoundKeys = JCSystem.makeTransientByteArray((short)300, JCSystem.CLEAR_ON_RESET);
      MakeSBox();
    }

    // CALCULATION OF LOOKUP TABLES FOR REDUCING CODE SIZE
    private void MakeSBox() {
      byte   p = 1;
      short  q;
      short  i;

      // Alogtable AND Logtable TABLES
      for (i=0; i<256; ++i) {
          Alogtable[i]= p;
          Logtable[(p >= 0) ? p : (short) (256 + p)]= (byte) i;
          p=(byte) (p^(p<<1)^(((p&0x80) == 0) ? 0: 0x01b));
      }
      // CORRECTION OF GENERATED LOG TABLE IS NEEDED
      Logtable[1] = 0;

      // SBox AND SiBox TABLES
      for (i=0; i<256; ++i)  {
         p= ((i == 0) ? 0 : (Alogtable[(short) (255-((Logtable[i] >= 0) ? Logtable[i] : (short) (256 + Logtable[i])))]));
         q= (p >= 0) ? p : (short) (256 + p);
         q= (short) ((q>>7) | (q<<1)); p^= (byte) q;
         q= (short) ((q>>7) | (q<<1)); p^= (byte) q;
         q= (short) ((q>>7) | (q<<1)); p^= (byte) q;
         q= (short) ((q>>7) | (q<<1)); p^= (byte) q;
         p= (byte) (p^0x63);
         SBox[i] =  p;
         SiBox[(p >= 0) ? p : (short) (256 + p)] = (byte) i;
      }

      // CONVERT LogTable FROM byte-oriented value into short-oriented
      for (i=0; i<256; ++i) {
        if (Logtable[i] < 0) Logtable[i] = (short) (256 + Logtable[i]);
      }


    }

    /**
     * Sechedule AES round keys fro given key material
     * @param key ... key array
     * @param keyOffset ... start offset in key array
     * @param aesRoundKeys ... array to hold scheduled keys
     */
    private void RoundKeysSchedule(byte key[], short keyOffset, byte aesRoundKeys[]) {
      byte     i;
      byte     j;
      byte     round;
      byte     rconpointer = 0;
      short    sourceOffset = 0;
      short    targetOffset = 0;


      short    hlp = 0;

      // FIRST KEY (SAME AS INPUT KEY)
      Util.arrayCopyNonAtomic(key, keyOffset, aesRoundKeys, (short) 0, STATELEN);

      // 10 ROUNDS KEYS
      for (round = 1; round <= N_ROUNDS; round++) {
          // TIME REDUCING PRECALCULATION
          hlp += STATELEN;

          // COPY KEY FOR round - 1 TO BUFFER FOR round
          Util.arrayCopyNonAtomic(aesRoundKeys, (short) ((round - 1) * STATELEN), aesRoundKeys, hlp, STATELEN);

          rconpointer = (byte) (round - 1);

          for (i = 0; i < 4; i++) {
            sourceOffset = (short) ( ((i + 1) % 4) + ((KEYN-1) * 4) + hlp );
            targetOffset = (short) ( i + (0 * 4) + hlp );
            aesRoundKeys[targetOffset] ^= SBox[(aesRoundKeys[sourceOffset] >= 0) ? aesRoundKeys[sourceOffset] : (short) (256 + aesRoundKeys[sourceOffset])];
          }

          aesRoundKeys[hlp] ^= rcon[rconpointer];

          for (j = 1; j < KEYN; j++) {
              for (i = 0; i < 4; i++) {
                sourceOffset = (short) (i + ((j - 1) * 4) + hlp);
                targetOffset = (short) ((i + (j * 4)) + hlp);
                aesRoundKeys[targetOffset] ^= aesRoundKeys[sourceOffset];
              }
          }
      }
    }


    // SHIFTING ROWS
    private void ShiftRow(byte a[], short dataOffset, byte d) {
      byte i, j;
      // ALSO FIRST ROUND IS SHIFTED (BUT BY 0 POSITIONS) DUE TO POSSIBILITY FOR USING Util.arrayCopy() LATER
      // tempBuffer WILL CONTAINS SHIFTED STATE a
      for(i = 0; i < 4; i++) {
          for(j = 0; j < BLOCKN; j++) tempBuffer[(short) (i + j * 4)] = a[(short) (((i + (byte) ((j + shifts[(short) (i + d*4)] % BLOCKN) * 4)) % STATELEN) + dataOffset)];
      }
      Util.arrayCopyNonAtomic(tempBuffer, (short) 0, a, dataOffset, STATELEN);
    }


    // MIXING COLUMNS
    private void MixColumn(byte a[], short dataOffset) {
      byte  i = 0, j = 0;
      // hlp CONTAINS PRECALCULATED EXPRESSION ((j * 4) + dataOffset)
      short hlp = dataOffset;
      // hlp2 CONTAINS PRECALCULATED EXPRESSION (j * 4)
      byte hlp2 = -4;
      byte hlp3 = 0;
      short tempVal = 0;
      short tempVal2 = 0;
      short a0 = 0;
      short a1 = 0;
      short a2 = 0;
      short a3 = 0;

      hlp -= 4;
      for(j = 0; j < BLOCKN; j++) {
        // TIME REDUCING PRECALCULATION
        hlp += 4; hlp2 += 4;

       // UNROLLED LOOP: for (i = 0; i < 4; i++)
        // ax WILL CONTAIN VALUE OF 'a[(short) (((i + x) % 4) + hlp)];' TRANSFORMED FROM byte TO short (via TAUB-like function)
          a0 = a[hlp]; a0 = (a0 >= 0) ? a0 : (short) (256 + a0);
          a1 = a[(short) (1 + hlp)]; a1 = (a1 >= 0) ? a1 : (short) (256 + a1);
          a2 = a[(short) (2 + hlp)]; a2 = (a2 >= 0) ? a2 : (short) (256 + a2);
          a3 = a[(short) (3 + hlp)]; a3 = (a3 >= 0) ? a3 : (short) (256 + a3);


          tempBuffer[hlp2] = (a0 != 0) ? Alogtable[(short) ((short) (Logtable[2] + Logtable[a0]) % 255)] : (byte) 0;

          if (a1 != 0) tempBuffer[hlp2] ^= Alogtable[(short) ((short) (Logtable[3] + Logtable[a1]) % 255)];
          tempBuffer[hlp2] ^= a2;
          tempBuffer[hlp2] ^= a3;


          hlp3 = (byte) (hlp2 + 1);


          tempBuffer[hlp3] = (a1 != 0) ? Alogtable[(short) ((short) (Logtable[2] + Logtable[a1]) % 255)] : (byte) 0;

          if (a2 != 0) tempBuffer[hlp3] ^= Alogtable[(short) ((short) (Logtable[3] + Logtable[a2]) % 255)];
          tempBuffer[hlp3] ^= a3;
          tempBuffer[hlp3] ^= a0;


          hlp3 = (byte) (hlp2 + 2);

          tempBuffer[hlp3] = (a2 != 0) ? Alogtable[(short) ((short) (Logtable[2] + Logtable[a2]) % 255)] : (byte) 0;

          if (a3 != 0) tempBuffer[hlp3] ^= Alogtable[(short) ((short) (Logtable[3] + Logtable[a3]) % 255)];
          tempBuffer[hlp3] ^= a0;
          tempBuffer[hlp3] ^= a1;


          hlp3 = (byte) (hlp2 + 3);

          tempBuffer[hlp3] = (a3 != 0) ? Alogtable[(short) ((short) (Logtable[2] + Logtable[a3]) % 255)] : (byte) 0;

          if (a0 != 0) tempBuffer[hlp3] ^= Alogtable[(short) ((short) (Logtable[3] + Logtable[a0]) % 255)];
          tempBuffer[hlp3] ^= a1;
          tempBuffer[hlp3] ^= a2;



      }

      Util.arrayCopyNonAtomic(tempBuffer, (short) 0, a, dataOffset, STATELEN);
    }

    // INVERSE OF MIXING COLUMNS
    private void InvMixColumn(byte a[], short dataOffset) {
      byte i = 0, j = 0;
      // hlp CONTAINS PRECALCULATED EXPRESSION ((j * 4) + dataOffset)
      short hlp = dataOffset;
      // hlp2 CONTAINS PRECALCULATED EXPRESSION (j * 4)
      byte hlp2 = -4;
      byte hlp3 = 0;
      short a0 = 0;
      short a1 = 0;
      short a2 = 0;
      short a3 = 0;

      hlp -= 4;
      for(j = 0; j < BLOCKN; j++) {
        // TIME REDUCING PRECALCULATION
        hlp += 4; hlp2 += 4;
/*
        // TODO: UNROLL THIS LOOP:
        for(i = 0; i < 4; i++) {
          tempBuffer[(byte) (i + hlp2)] = (byte) mul((byte) 0xe, a[(short) (i + hlp)]);
          tempBuffer[(byte) (i + hlp2)] ^= (byte) mul((byte) 0xb, a[(short) (((i + 1) % 4) + hlp)]);
          tempBuffer[(byte) (i + hlp2)] ^= (byte) mul((byte) 0xd, a[(short) (((i + 2) % 4) + hlp)]);
          tempBuffer[(byte) (i + hlp2)] ^= (byte) mul((byte) 0x9, a[(short) (((i + 3) % 4) + hlp)]);
        }
/**/
          // UNROLLED LOOP
          a0 = a[hlp]; a0 = (a0 >= 0) ? a0 : (short) (256 + a0);
          a1 = a[(short) (1 + hlp)]; a1 = (a1 >= 0) ? a1 : (short) (256 + a1);
          a2 = a[(short) (2 + hlp)]; a2 = (a2 >= 0) ? a2 : (short) (256 + a2);
          a3 = a[(short) (3 + hlp)]; a3 = (a3 >= 0) ? a3 : (short) (256 + a3);

          // i == 0
          //tempBuffer[hlp2] = (byte) mul((byte) 0xe, a0);
          tempBuffer[hlp2] = (a0 != 0) ? Alogtable[(short) ((short) (Logtable[0xe] + Logtable[a0]) % 255)] : (byte) 0;
          //tempBuffer[hlp2] ^= (byte) mul((byte) 0xb, a1);
          tempBuffer[hlp2] ^= (a1 != 0) ? Alogtable[(short) ((short) (Logtable[0xb] + Logtable[a1]) % 255)] : (byte) 0;
          //tempBuffer[hlp2] ^= (byte) mul((byte) 0xd, a2);
          tempBuffer[hlp2] ^= (a2 != 0) ? Alogtable[(short) ((short) (Logtable[0xd] + Logtable[a2]) % 255)] : (byte) 0;
          //tempBuffer[hlp2] ^= (byte) mul((byte) 0x9, a3);
          tempBuffer[hlp2] ^= (a3 != 0) ? Alogtable[(short) ((short) (Logtable[0x9] + Logtable[a3]) % 255)] : (byte) 0;

          // i == 1
          hlp3 = (byte) (hlp2 + 1);
          //tempBuffer[hlp3] = (byte) mul((byte) 0xe, a1);
          tempBuffer[hlp3] = (a1 != 0) ? Alogtable[(short) ((short) (Logtable[0xe] + Logtable[a1]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0xb, a2);
          tempBuffer[hlp3] ^= (a2 != 0) ? Alogtable[(short) ((short) (Logtable[0xb] + Logtable[a2]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0xd, a3);
          tempBuffer[hlp3] ^= (a3 != 0) ? Alogtable[(short) ((short) (Logtable[0xd] + Logtable[a3]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0x9, a0);
          tempBuffer[hlp3] ^= (a0 != 0) ? Alogtable[(short) ((short) (Logtable[0x9] + Logtable[a0]) % 255)] : (byte) 0;

          // i == 2
          hlp3 = (byte) (hlp2 + 2);
          //tempBuffer[hlp3] = (byte) mul((byte) 0xe, a2);
          tempBuffer[hlp3] = (a2 != 0) ? Alogtable[(short) ((short) (Logtable[0xe] + Logtable[a2]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0xb, a3);
          tempBuffer[hlp3] ^= (a3 != 0) ? Alogtable[(short) ((short) (Logtable[0xb] + Logtable[a3]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0xd, a0);
          tempBuffer[hlp3] ^= (a0 != 0) ? Alogtable[(short) ((short) (Logtable[0xd] + Logtable[a0]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0x9, a1);
          tempBuffer[hlp3] ^= (a1 != 0) ? Alogtable[(short) ((short) (Logtable[0x9] + Logtable[a1]) % 255)] : (byte) 0;

          // i == 3
          hlp3 = (byte) (hlp2 + 3);
          //tempBuffer[hlp3] = (byte) mul((byte) 0xe, a3);
          tempBuffer[hlp3] = (a3 != 0) ? Alogtable[(short) ((short) (Logtable[0xe] + Logtable[a3]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0xb, a0);
          tempBuffer[hlp3] ^= (a0 != 0) ? Alogtable[(short) ((short) (Logtable[0xb] + Logtable[a0]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0xd, a1);
          tempBuffer[hlp3] ^= (a1 != 0) ? Alogtable[(short) ((short) (Logtable[0xd] + Logtable[a1]) % 255)] : (byte) 0;
          //tempBuffer[hlp3] ^= (byte) mul((byte) 0x9, a2);
          tempBuffer[hlp3] ^= (a2 != 0) ? Alogtable[(short) ((short) (Logtable[0x9] + Logtable[a2]) % 255)] : (byte) 0;
        // END OF UNROLLED LOOP /**/
      }

      Util.arrayCopyNonAtomic(tempBuffer, (short) 0, a, dataOffset, STATELEN);
    }


     /**
      * Encrypt one block, key schedule must be already processed
      * @param data ... data array to be encrypted
      * @param dataOffset ... start offset in data array
      * @param aesRoundKeys ... scheduled keys for AES (from RoundKeysSchedule() function)
      * @return true if encrypt success, false otherwise.
      */
     private boolean AESEncryptBlock(byte data[], short dataOffset, byte[] aesRoundKeys) {
        byte r;
        byte i;
        short keysOffset = 0;

        // *** ADD ROUND KEY
        //KeyAddition(data, dataOffset, roundKeys, (byte) 0);
        for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] ^= aesRoundKeys[i];

        // N_ROUNDS-1 ORDINARY ROUNDS
        for(r = 1; r < N_ROUNDS; r++) {
            keysOffset += STATELEN;

            // *** SUBSTITUTION
            //Substitution(data, dataOffset, SBox);
            for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] = SBox[((data[(short) (i + dataOffset)] >= 0) ? data[(short) (i + dataOffset)] : (short) (256 + data[(short) (i + dataOffset)]))] ;

            // *** SHIFT ROW
            ShiftRow(data, dataOffset, (byte) 0);

            // *** MIX COLUMN
            MixColumn(data, dataOffset);

            // *** ADD ROUND KEY
            // KeyAddition(data, dataOffset, roundKeys, (short) (r * STATELEN));
            for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] ^= aesRoundKeys[(short) (i + keysOffset)];
        }

        // *** NO MIXCOLUMN IN LAST ROUND

        // *** SUBSTITUTION
        //Substitution(data, dataOffset, SBox);
        for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] = SBox[((data[(short) (i + dataOffset)] >= 0) ? data[(short) (i + dataOffset)] : (short) (256 + data[(short) (i + dataOffset)]))] ;

        // *** SHIFT ROW
        ShiftRow(data, dataOffset, (byte) 0);

        // *** ADD ROUND KEY
        //KeyAddition(data, dataOffset, roundKeys, (short) (N_ROUNDS * STATELEN));
        keysOffset += STATELEN;
        for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] ^= aesRoundKeys[(short) (i + keysOffset)];

        return true;
     }

     /**
      * Decrypt one block, key schedule must be already processed
      * @param data
      * @param dataOffset
      * @param aesRoundKeys ... scheduled keys for AES (from RoundKeysSchedule() function)
      * @return true if decrypt success, false otherwise.
      */
     private boolean AESDecryptBlock(byte data[], short dataOffset, byte[] aesRoundKeys) {
        byte  r;
        short i;
        short keysOffset = 0;

        // *** ADD ROUND KEY
        //KeyAddition(data, dataOffset, roundKeys, (short) (N_ROUNDS * STATELEN));
        keysOffset = (short) (N_ROUNDS * STATELEN);
        for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] ^= aesRoundKeys[(short) (i + keysOffset)];

        // *** SHIFT ROW
        ShiftRow(data, dataOffset, (byte) 1);

        // *** SUBSTITUTION
        // Substitution(data, dataOffset, SiBox);
        for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] = SiBox[((data[(short) (i + dataOffset)] >= 0) ? data[(short) (i + dataOffset)] : (short) (256 + data[(short) (i + dataOffset)]))] ;

        for(r = (byte) (N_ROUNDS-1); r > 0; r--) {
            keysOffset -= STATELEN;

            // *** ADD ROUND KEY
            // KeyAddition(data, dataOffset, roundKeys, (short) (r * STATELEN));
            for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] ^= aesRoundKeys[(short) (i + keysOffset)];

            // *** INVERSE MIX COLUMN
            InvMixColumn(data, dataOffset);

            // *** SHIFT ROW
            ShiftRow(data, dataOffset, (byte) 1);

            // *** SUBSTITUTION
            // Substitution(data, dataOffset, SiBox);
            for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] = SiBox[((data[(short) (i + dataOffset)] >= 0) ? data[(short) (i + dataOffset)] : (short) (256 + data[(short) (i + dataOffset)]))] ;
        }

        // *** ADD ROUND KEY
        //KeyAddition(data, dataOffset, roundKeys, (byte) 0);
        for (i = 0; i < STATELEN; i++) data[(short) (i + dataOffset)] ^= aesRoundKeys[i];

        return true;
     }

     //if initialized by this method the IV is set to 16 times 0x00
    public void init(Key initkey, byte mode) throws CryptoException
    {
        if(!initkey.isInitialized())
        {
            throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        }
        if(initkey.getSize()!=128 || initkey.getType()!= KeyBuilder.TYPE_DES)
        {
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        this.mode =mode;
        cipherKey = (DESKey)initkey;
        Util.arrayFillNonAtomic(m_IV,(short)0,(short)16,(byte)0x00);
        isInitialized=true;
    }


    //AES needs IV, init using this for user defined IV, first 16 bytes of buf used as IV
    public void init(Key initkey, byte mode, byte[] buf, short bOff, short bLen) throws CryptoException {

         if(!initkey.isInitialized())
        {
            throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        }
        if(initkey.getSize()!=16 && initkey.getType()!= KeyBuilder.TYPE_DES && bLen !=16)
        {
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        this.mode =mode;
        cipherKey = (DESKey)initkey;
        Util.arrayCopyNonAtomic(buf,bOff,m_IV,(short)0,bLen);
        isInitialized=true;
    }

    public byte getAlgorithm() {
        return ALG_JCAES;
    }

    public short doFinal(byte[] inBuff, short inOffset, short inLength,
                         byte[] outBuff, short outOffset) throws CryptoException {
        //not initialized
        if(!isInitialized)
        {
            throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        }
        if(inLength!=16)
        {
            throw new CryptoException(CryptoException.ILLEGAL_USE);
        }
        if(mode==Cipher.MODE_ENCRYPT)
        {
            cipherKey.getKey(temp,(short)0);
            RoundKeysSchedule(temp,(short)0,aesRoundKeys);
            Util.arrayCopy(inBuff,inOffset,temp,(short)0,(short)16);
            AESEncryptBlock(temp,(short)0,aesRoundKeys);
            Util.arrayCopy(temp,(short)0,outBuff,outOffset,(short)16);
            //cleaning of RAM memory
            Util.arrayFillNonAtomic(temp, (byte)0, (byte) 16, (byte) 0x00); //reset to zero
            Util.arrayFillNonAtomic(aesRoundKeys, (byte)0, (byte) 300, (byte) 0x00); //reset to zero
            return (short)16;
        }
        else //decrypt
        {
            cipherKey.getKey(temp,(short)0);
            RoundKeysSchedule(temp,(short)0,aesRoundKeys);
            Util.arrayCopy(inBuff,inOffset,temp,(short)0,(short)16);
            AESDecryptBlock(temp,(short)0,aesRoundKeys);
            Util.arrayCopy(temp,(short)0,outBuff,outOffset,(short)16);
            //cleaning of RAM memory
            Util.arrayFillNonAtomic(temp, (byte)0, (byte) 16, (byte) 0x00); //reset to zero
            Util.arrayFillNonAtomic(aesRoundKeys, (byte)0, (byte) 300, (byte) 0x00); //reset to zero
            return (short)16;
        }
    }

    //always throw crypto exception
    //not using this function
    public short update(byte[] bytes, short i, short i1, byte[] bytes1, short i2) throws CryptoException {
        return 0;
    }
}