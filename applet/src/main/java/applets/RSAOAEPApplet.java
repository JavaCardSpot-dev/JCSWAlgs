package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class RSAOAEPApplet  extends Applet
        implements IConsts{
    boolean         m_isRealCard = false;
    final static short ARRAY_LENGTH                   = (short) 300;
    private byte m_ramArray[] = null;
    private byte m_ramArray2[] = null;
    private   byte      m_dataArray[] = null;
    Cipher                  m_rsaEngine = null;
    MessageDigest           m_hash  = null;
    RandomData              m_secureRandom = null;
    KeyPair                 m_rsaKeyPair = null;
    RSAPublicKey            m_rsaPubKey = null;
    RSAPrivateKey        m_rsaPrivKey = null;
    RSAOAEP                 m_rsaOAEP = null;

    protected RSAOAEPApplet(byte[] buffer, short offset, byte length)
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

            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            m_rsaEngine = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

            //if (m_isRealCard == true) {
                //For real cards: we need new instance when generating completelly new key:
            m_rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
           /* } else {
                // For simulated cards - create KeyPair from two keys
                m_rsaPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
                m_rsaPrivKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
                m_rsaKeyPair = new KeyPair(m_rsaPubKey, m_rsaPrivKey);
            }*/

            m_rsaKeyPair.genKeyPair();
            m_rsaPubKey = (RSAPublicKey) m_rsaKeyPair.getPublic();
            m_rsaPrivKey = (RSAPrivateKey) m_rsaKeyPair.getPrivate();

            m_rsaOAEP = RSAOAEP.getInstance(m_rsaEngine, m_hash, m_secureRandom, null, null);

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
        }

        register();

    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new RSAOAEPApplet(bArray, bOffset, bLength);
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
            case IConsts.OFFSET_INS_RSAOAEP:
                processRSAOEAP(apdu);
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
}