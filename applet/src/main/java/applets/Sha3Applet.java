package applets;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

//public class Sha3Applet {
//}

//package applets;

//import com.sun.javacard.impl.PackageEntry;

        import javacard.framework.*;

public class Sha3Applet extends Applet
        implements IConsts {
    private Sha3Applet()
    {

    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new Sha3Applet().register();
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



  /*  private void processLight(APDU apdu)
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
                        TwineCipher m_instance = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80);
                        len_data  = m_instance.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case TWINE_CIPHER_128:
                        TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80); //TODO change that
                        return;
                    case ZORRO_CIPHER:
                        ZorroCipher m_instance_zorro = ZorroCipher.getInstance();
                        len_data  = m_instance_zorro.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;

                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_DEC:
                switch(type)
                {
                    case TwineCipher.TWINE_CIPHER_80:
                        TwineCipher m_instance = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80);
                        len_data  = m_instance.process(TwineCipher.OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case TwineCipher.TWINE_CIPHER_128:
                        TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80); //TODO change that
                        return;
                    case ZORRO_CIPHER:
                        ZorroCipher m_instance_zorro = ZorroCipher.getInstance();
                        len_data  = m_instance_zorro.process(OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                        return;
                }
            case OFFSET_P1_GEN:
                switch(type)
                {
                    case TwineCipher.TWINE_CIPHER_80:
                        TwineCipher m_instance = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80);
                        len_data = m_instance.process(TwineCipher.OFFSET_P1_GEN, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
                        return;
                    case TwineCipher.TWINE_CIPHER_128:
                        TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80); //TODO change that
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
*/
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
        }
    }


}