package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

import java.lang.reflect.Array;
import java.util.Arrays;

public class JavaCardApplet  extends Applet
        implements IConsts{
    boolean         m_isRealCard = false;
    final static short ARRAY_LENGTH                   = (short) 300;
    final static byte  AES_BLOCK_LENGTH               = (short) 0x16;
    private byte m_ramArray[] = null;
    private byte m_ramArray2[] = null;
    private   byte      m_dataArray[] = null;
    Cipher                  m_rsaEngine = null;
    MessageDigest           m_hash  = null;
    RandomData              m_secureRandom = null;
    KeyPair                 m_rsaKeyPair = null;
    RSAPublicKey            m_rsaPubKey = null;
    RSAPrivateCrtKey        m_rsaPrivKey = null;
    RSAOAEP                 m_rsaOAEP = null;
    TwineCipher m_TwineCipher = null;
    ZorroCipher m_ZorroCipher = null;
    JavaCardAES m_aesCipher = null;
    InitializedMessageDigest m_Sha512 = null;

    private byte[] m_aes_key=null;
    protected JavaCardApplet(byte[] buffer, short offset, byte length)
    {
        short dataOffset = offset;

        if(length > 9) {
            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);
            // go to proprietary data
            dataOffset++;

            if (length == 15) {
                // We have simulator
                m_isRealCard = false;
            } else {
                // This is real card
                m_isRealCard = true;
            }

            m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);

            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            m_rsaEngine = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

            if (m_isRealCard == true) {
                //For real cards: we need new instance when generating completelly new key:
                m_rsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
            } else {
                // For simulated cards - create KeyPair from two keys
                m_rsaPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
                m_rsaPrivKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
                m_rsaKeyPair = new KeyPair(m_rsaPubKey, m_rsaPrivKey);
            }

            m_rsaKeyPair.genKeyPair();
            m_rsaPubKey = (RSAPublicKey) m_rsaKeyPair.getPublic();
            m_rsaPrivKey = (RSAPrivateCrtKey) m_rsaKeyPair.getPrivate();

            m_rsaOAEP = RSAOAEP.getInstance(m_rsaEngine, m_hash, m_secureRandom, null, null);

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            Util.arrayCopyNonAtomic(buffer,dataOffset,m_dataArray,(short)0,(short)+10);
            m_TwineCipher = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80,m_dataArray);   //Setting Twine Cipher to the first 10 bytes of user data from installation
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            m_ZorroCipher= ZorroCipher.getInstance();

            m_aesCipher = new JavaCardAES();
            m_aesCipher.m_IV=new byte[16];
            Util.arrayCopyNonAtomic(buffer,dataOffset,m_dataArray,(short)0,(short)16);
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            m_aesCipher.m_IVOffset=0;
            m_aes_key = new byte[16];
            Util.arrayCopyNonAtomic(buffer,dataOffset,m_aes_key,(short)0,(short)16);
            m_Sha512 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_512, false);
            Sha512.init();
        }

        register();

    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new JavaCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if(buf[ISO7816.OFFSET_CLA] != IConsts.OFFSET_CLA_APPLICATION)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
        short read = apdu.setIncomingAndReceive();
        while(read < lc) {
            read += apdu.receiveBytes(read);
        }
        switch (buf[ISO7816.OFFSET_INS])
        {
            case IConsts.OFFSET_INS_LIGHT:
                processLight(apdu);
                return;
            case IConsts.OFFSET_INS_RSAOAEP:
                processRSAOEAP(apdu);
                return;
            case IConsts.OFFSET_INS_HASH:
                processHash(apdu);
                return;
            default:
                break;
        }
    }
    short m_wrapLen = 0;
    byte dataLen = 0;
    void processRSAOEAP(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        dataLen = buffer[ISO7816.OFFSET_LC];
       // short len = apdu.setIncomingAndReceive();
        Util.arrayCopyNonAtomic(buffer,ISO7816.OFFSET_CDATA,m_ramArray,(short)0,dataLen);
        if (buffer[ISO7816.OFFSET_P1] == RSAOAEP_ENC) {
            m_rsaOAEP.init(m_rsaPubKey, Cipher.MODE_ENCRYPT);
            m_wrapLen = m_rsaOAEP.doFinal(m_ramArray, (short) 0, dataLen, m_ramArray2, (short) 0);
            Util.arrayCopyNonAtomic(m_ramArray2,(short)0,buffer,ISO7816.OFFSET_CDATA,(short)32);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)32);
            return;
        }
        if (buffer[ISO7816.OFFSET_P1] == RSAOAEP_DEC) {
            // Assumption: properly wrapped data in m_ramArray2 from previous run of Test_RSAOEAP_performance encode
            m_rsaOAEP.init(m_rsaPrivKey, Cipher.MODE_DECRYPT);
            short unwrapLen = m_rsaOAEP.doFinal(m_ramArray2, (short) 0, m_wrapLen, m_ramArray, (short) 0);
            Util.arrayCopyNonAtomic(m_ramArray,(short)0,buffer,ISO7816.OFFSET_CDATA,(short)16);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, unwrapLen);
        }
    }


    private void processLight(APDU apdu)
    {
        //cla and ins are proccessed
        byte[] buf = apdu.getBuffer();
        byte state = (buf[ISO7816.OFFSET_P1]);
        byte type = (buf[ISO7816.OFFSET_P2]);
        byte count_data = buf[ISO7816.OFFSET_LC];
        if(count_data == 0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short len_data = -1;
        switch(state)
        {
            case OFFSET_P1_ENC:
                switch(type)
                {
                    case TWINE_CIPHER_80:
                        len_data  = m_TwineCipher.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case ZORRO_CIPHER:
                        len_data  = m_ZorroCipher.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case AES_CIPHER:
                        m_aesCipher.RoundKeysSchedule(m_aes_key,(short)0,m_ramArray);
                        m_aesCipher.AESEncryptBlock(buf,(short)(ISO7816.OFFSET_CDATA),m_ramArray);
                        Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)16);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_DEC:
                switch(type)
                {
                    case TwineCipher.TWINE_CIPHER_80:
                        len_data  = m_TwineCipher.process(TwineCipher.OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case ZORRO_CIPHER:
                        len_data  = m_ZorroCipher.process(OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case AES_CIPHER:
                        m_aesCipher.RoundKeysSchedule(m_aes_key,(short)0,m_ramArray);
                        m_aesCipher.AESDecryptBlock(buf,(short)(ISO7816.OFFSET_CDATA),m_ramArray);
                        Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)16);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_GEN:
                switch(type)
                {
                    case TwineCipher.TWINE_CIPHER_80:
                        len_data = m_TwineCipher.process(TwineCipher.OFFSET_P1_GEN, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case AES_CIPHER:
                        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA), m_aes_key,(short) 0,(short)16);
                        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 16), m_aesCipher.m_IV,(short) 0,(short)16);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            default:
                break;
        }
    }

    private void processTest(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte state = (buf[ISO7816.OFFSET_P1]);
        byte type = (buf[ISO7816.OFFSET_P2]);
        short count_data = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
        if(count_data < 0)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        TestCase m_Instance = TestCase.getInstance();
        switch(state)
        {
            case CMD_TEST_LOOP_INC:
                m_Instance.runInc();
                break;
            case CMD_TEST_LOOP_DEC:
                m_Instance.runDec();
                break;
            case CMD_TEST_WRITE_RAM_DESELECT:
                m_Instance.testWriteRamRamDeselect();
                break;
            case CMD_TEST_WRITE_RAM_RESET:
                m_Instance.testWriteRamRamReset();
                break;
            default:
                break;

        }
    }

    private void processHash(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte state = (buf[ISO7816.OFFSET_P1]);
        byte type = (buf[ISO7816.OFFSET_P2]);
        byte count_data = buf[ISO7816.OFFSET_LC];
        if(count_data == 0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short len_data = -1;
        switch(state)
        {
            case IConsts.HASH_KECCAK_160:
            {
                Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_160);
                cipherHash.postInit();
                len_data  = cipherHash.process(HASH, buf, (ISO7816.OFFSET_CDATA), count_data);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                return;
            }
            case IConsts.HASH_KECCAK_r144c256:
            {
                Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r144c256);
                cipherHash.postInit();
                len_data  = cipherHash.process(HASH, buf, (ISO7816.OFFSET_CDATA), count_data);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                return;
            }
            case IConsts.HASH_KECCAK_r128c272:
            {
                Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r128c272);
                cipherHash.postInit();
                len_data  = cipherHash.process(HASH, buf, (ISO7816.OFFSET_CDATA), count_data);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                return;
            }
            case IConsts.HASH_KECCAK_r544c256:
            {
                Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r544c256);
                cipherHash.postInit();
                len_data  = cipherHash.process(HASH, buf, (ISO7816.OFFSET_CDATA), count_data);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                return;
            }
            case IConsts.HASH_KECCAK_r512c288:
            {
                Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r512c288);
                cipherHash.postInit();
                len_data  = cipherHash.process(HASH, buf, (ISO7816.OFFSET_CDATA), count_data);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                return;
            }
            case IConsts.HASH_KECCAK_r256c544:
            {
                Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r256c544);
                cipherHash.postInit();
                len_data  = cipherHash.process(HASH, buf, (ISO7816.OFFSET_CDATA), count_data);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                return;
            }
            case IConsts.HASH_SHA512:
            {
                Util.arrayFillNonAtomic(m_ramArray, (short) 0, ARRAY_LENGTH, (byte) 0);
                Util.arrayCopyNonAtomic(buf,(ISO7816.OFFSET_CDATA),m_ramArray,(short)0,count_data);
                m_Sha512.reset();
                m_Sha512.doFinal(m_ramArray, (short)0, count_data, buf,(ISO7816.OFFSET_CDATA));
                //Sha512.resetUpdateDoFinal(m_ramArray, (short)0, count_data, buf,(ISO7816.OFFSET_CDATA));
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)MessageDigest.LENGTH_SHA_512);
            }
            default:
                break;
        }
    }


}

