package applets;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class AES_CBC_Applet extends Applet implements IConsts{
    DESKey m_key = null;
    JavaCardAES m_aes_enc = null;
    JavaCardAES m_aes_dec = null;
    boolean         m_isRealCard = false;
    private byte m_ramArray[] = null;
    final static short ARRAY_LENGTH  = (short) 256;
    private byte[] m_iv=null; //iv buffer
    private byte [] inter =null; //intermediate result buffer
    private byte [] inter2 =null; //intermediate result buffer
    protected AES_CBC_Applet(byte[] buffer, short offset, byte length) {

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
           // m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            m_key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES3_2KEY,false);
            //m_zorro_enc= new ZorroCipher();
            //m_zorro_dec = new ZorroCipher();
            //m_twine_enc = new TwineCipher();
            //m_twine_dec = new TwineCipher();
            m_aes_enc = new JavaCardAES();
            m_aes_dec = new JavaCardAES();
            m_iv=new byte[16];
            inter = new byte[16];
            inter2 = new byte[16];

        }

    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException
    {
        new AES_CBC_Applet(bArray, bOffset, bLength).register();

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
                    case AES_CIPHER:
                        len_data= encrypt(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_DEC:
                switch(type)
                {
                    case AES_CIPHER:
                        len_data= decrypt(buf,(short)(ISO7816.OFFSET_CDATA),count_data,m_ramArray,(short)0);
                        Util.arrayCopy(m_ramArray,(short)0,buf,ISO7816.OFFSET_CDATA,len_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_GEN:
                switch(type)
                {
                    case AES_CIPHER:
                        m_key.setKey(buf,(short)(ISO7816.OFFSET_CDATA));
                        m_aes_enc.init(m_key,Cipher.MODE_ENCRYPT);
                        m_aes_dec.init(m_key,Cipher.MODE_DECRYPT);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            default:
                break;
        }
    }
    private short encrypt(byte[] inbuf, short inoff,short len, byte[] outbuf,short outoff)
    {
        //short len_data;
        Util.arrayFillNonAtomic(m_iv,(short)0,(short)16,(byte)0x11);//default IV of zero
        short pad=0;
        if(len%16!=0) {
            Util.arrayFillNonAtomic(inbuf, (short) (inoff + len), (short) (16 - (len % 16)), (byte) 0x00); //zero padding
            pad=(short)(16 - (len % 16));
        }
        for(short pos=0;pos<len;pos=(short)(pos+16))
        {
                Util.arrayCopy(inbuf,(short)(pos+inoff),inter,(short)0,(short)16);
                xor_16_buf(inter,m_iv);
                m_aes_enc.doFinal(inter,(short)0,(short)16,inter,(short)0);
                Util.arrayCopy(inter,(short)(0),outbuf,(short)(pos+outoff),(short)16);
                Util.arrayCopy(inter,(short)(0),m_iv,(short)0,(short)16);

        }
        return (short)(len+pad);

    }
    private void xor_16_buf(byte[] x, byte[] y)
    {
        for(short i =0;i<16;i++)
            x[i]=(byte)(x[i] ^ y[i]);
    }

    private short decrypt(byte[] inbuf, short inoff,short len, byte[] outbuf,short outoff)
    {
        Util.arrayFillNonAtomic(m_iv,(short)0,(short)16,(byte)0x11);//default IV of zero
        if(len%16!=0) {
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        for(short pos=0;pos<len;pos=(short)(pos+16))
        {
            Util.arrayCopy(inbuf,(short)(pos+inoff),inter,(short)0,(short)16);
            Util.arrayCopy(inter,(short)(0),inter2,(short)0,(short)16);
            m_aes_dec.doFinal(inter,(short)0,(short)16,inter,(short)0);
            xor_16_buf(inter,m_iv);
            Util.arrayCopy(inter2,(short)(0),m_iv,(short)0,(short)16);
            Util.arrayCopy(inter,(short)(0),outbuf,(short)(pos+outoff),(short)16);
        }
        return len;
    }
    public boolean select() {
        return true;
    }

    public void deselect() {
    }
}


