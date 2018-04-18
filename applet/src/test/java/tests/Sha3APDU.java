package tests;

import applets.Sha3Applet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;



import applets.Sha3Applet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import com.google.common.primitives.Bytes;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;

/**
 *
 * @author Petr Svenda petr@svenda.com
 */
public class Sha3APDU {

    //private final static byte SELECT_TESTAPPLET[] = Util.hexStringToByteArray("5365637572654a617662");
    private static byte APPLET_AID[] = Util.hexStringToByteArray("4C6162616B4170706C6578");
    static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    public static void main(String[] args) {
        try {
            demoSingleCommand();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
        }
    }



    public static ResponseAPDU demoSingleCommand() throws Exception {

        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID);

        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        byte[] install_data=Util.hexStringToByteArray("00000000112233445566778899000000112233445566778899");
        // A) If running on physical card
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator
        runCfg.setAppletToSimulate(Sha3Applet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator
        runCfg.setbReuploadApplet(true);
        runCfg.setInstallData(install_data);

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        ResponseAPDU response;
        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
       System.out.println("Symmetric Block Ciphers: ");
        byte[] key;
        byte[] plain;

        System.out.println("Hash: ");
        plain=Util.hexStringToByteArray("00");  //only 50 bytes possible
       //ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00,0x11,0x23,0x32,aes_key_iv));
        //System.out.println(response);
        System.out.println("Keccak_160: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x40,0x00,plain));
        byte[]   plain_max=Util.hexStringToByteArray("60616263646566676869606162636465666768696061626364656667686960616263646566676869606162636465666768696061626364656667686960616263646566676869606162636465666768696061626364656667686960616263646566676869606162636465666768696061626364656667686960616263646566");
        byte[] Test_Vector1=Util.hexStringToByteArray("010000000058590e59bf419e1981b6");
        System.out.println("Keccak_160 (Round:1 Pre image): ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x40,0x00,Test_Vector1));
        System.out.println("KECCAK_r144c256: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x41,0x00,plain));
        System.out.println("KECCAK_r128c272: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x42,0x00,plain));
        System.out.println("KECCAK_r544c256: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x43,0x00,plain_max));
        System.out.println("KECCAK_r512c288: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x44,0x00,plain));
        System.out.println("KECCAK_r256c544: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x46,0x00,plain));
       // System.out.println("SHA512: ");
       // response =cardMngr.transmit(new CommandAPDU(0x00,0x24,0x47,0x00,plain));

       // System.out.println("Tests: ");
       // plain=Util.hexStringToByteArray("11111122222211");
       // response =cardMngr.transmit(new CommandAPDU(0x00,0x23,0x00,0x00,plain));


        return response;



    }

    /**
     * Sending command to the card.
     * Enables to send init commands before the main one.
     *
     * @param cardMngr
     * @param command
     * @param initCommands
     * @return
     * @throws CardException
     */
    public static ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<String> initCommands) throws CardException {
        if (initCommands != null) {
            for (String cmd : initCommands) {
                cardMngr.getChannel().transmit(new CommandAPDU(Util.hexStringToByteArray(cmd)));
            }
        }

        final ResponseAPDU resp = cardMngr.getChannel().transmit(new CommandAPDU(Util.hexStringToByteArray(command)));
        return resp;
    }
}