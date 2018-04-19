package applets;

import javacard.framework.*;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class CipherApplet extends Applet implements IConsts{
    DESKey m_key = null;
    ZorroCipher m_zorro_enc = null;
    ZorroCipher m_zorro_dec = null;
    TwineCipher m_twine_enc = null;
    TwineCipher m_twine_dec = null;
    JavaCardAES m_aes_enc = null;
    JavaCardAES m_aes_dec = null;
    boolean         m_isRealCard = false;
    private byte m_ramArray[] = null;
    private byte m_ramArray2[] = null;
    final static short ARRAY_LENGTH  = (short) 300;

    protected CipherApplet(byte[] buffer, short offset, byte length) {

        short dataOffset = offset;

        if (length > 9) {
         /*   // shift to privilege offset
            dataOffset += (short) (1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short) (1 + buffer[dataOffset]);
            // go to proprietary data
            dataOffset++;

            if (length == 15) {
                // We have simulator
                m_isRealCard = false;
            } else {
                // This is real card
                m_isRealCard = true;
            }*/
            m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            m_key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES3_2KEY,false);
            m_zorro_enc= new ZorroCipher();
            m_zorro_dec = new ZorroCipher();
            m_twine_enc = new TwineCipher();
            m_twine_dec = new TwineCipher();



        }

    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException
    {
        new CipherApplet(bArray, bOffset, bLength).register();

    }
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != IConsts.OFFSET_CLA_APPLICATION)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
        short read = apdu.setIncomingAndReceive();
        while (read < lc) {
            read += apdu.receiveBytes(read);
        }
        switch (buf[ISO7816.OFFSET_INS]) {
            case IConsts.OFFSET_INS_LIGHT:
                processLight(apdu);
                return;
            default:
                break;
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
                    case ZORRO_CIPHER:
                        len_data= m_zorro_enc.doFinal(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case TWINE_CIPHER_80:
                        len_data= m_twine_enc.doFinal(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    /*case AES_CIPHER:
                        len_data= m_aes_enc.doFinal(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;*/
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_DEC:
                switch(type)
                {
                    case ZORRO_CIPHER:
                        len_data= m_zorro_dec.doFinal(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case TWINE_CIPHER_80:
                        len_data= m_twine_dec.doFinal(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    /*case AES_CIPHER:
                        len_data= m_aes_dec.doFinal(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;*/
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_GEN:
                switch(type)
                {
                    case ZORRO_CIPHER:
                        m_key.setKey(buf,(short)(ISO7816.OFFSET_CDATA));
                        m_zorro_enc.init(m_key,Cipher.MODE_ENCRYPT);
                        m_zorro_dec.init(m_key,Cipher.MODE_DECRYPT);
                        return;
                    case TWINE_CIPHER_80:
                        m_key.setKey(buf,(short)(ISO7816.OFFSET_CDATA));
                        m_twine_enc.init(m_key,Cipher.MODE_ENCRYPT);
                        m_twine_dec.init(m_key,Cipher.MODE_DECRYPT);
                        return;
                    /*case AES_CIPHER:
                        m_key.setKey(buf,(short)(ISO7816.OFFSET_CDATA));
                        m_aes_enc.init(m_key,Cipher.MODE_ENCRYPT);
                        m_aes_dec.init(m_key,Cipher.MODE_DECRYPT);
                        return;*/
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            default:
                break;
        }
    }
    public boolean select() {
        return true;
    }

    public void deselect() {
    }
}


