package applets;

import javacard.framework.*;

public class Sha512Applet extends Applet
        implements IConsts {
    private byte m_ramArray[] = null;
    final static short ARRAY_LENGTH = (short) 300;
    private Sha512Applet()
    {
        m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
        Sha512.init();
    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new Sha512Applet().register();
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
        //processHash(apdu);
        switch (buf[ISO7816.OFFSET_INS])
        {
           case IConsts.OFFSET_INS_HASH:
                processHash(apdu);
                return;
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
            /*case IConsts.HASH_KECCAK_160:
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
            }*/
            case IConsts.HASH_SHA512:
            {
                Util.arrayFillNonAtomic(m_ramArray, (short) 0, ARRAY_LENGTH, (byte) 0);
                Util.arrayCopyNonAtomic(buf,(ISO7816.OFFSET_CDATA),m_ramArray,(short)0,count_data);
                Sha512.reset();
                Sha512.doFinal(m_ramArray, (short)0, count_data,buf,ISO7816.OFFSET_CDATA);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)64);
                return;
            }
            default:
                break;
        }
    }


}
