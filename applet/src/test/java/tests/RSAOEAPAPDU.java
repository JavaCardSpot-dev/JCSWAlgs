package tests;

import applets.RSAOAEPApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;

/**
 *
 * @author Petr Svenda petr@svenda.com
 */
public class RSAOEAPAPDU {

    private static byte APPLET_AID[] = Util.hexStringToByteArray("4C6162616B4170706C6577");
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
	
	
	
    public static ResponseAPDU  demoSingleCommand() throws Exception {

        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID);

        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        byte[] install_data=Util.hexStringToByteArray("00000000112233445566778899000000112233445566778899");
        // A) If running on physical card
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator
        runCfg.setAppletToSimulate(RSAOAEPApplet.class); // main class of applet to simulate
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


        System.out.println("RSA OAEP: ");
        System.out.println("Encode: ");
        plain=Util.hexStringToByteArray("11111122222211");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x25,0x51,0x00,plain));
        System.out.println("Decode: ");
        response =cardMngr.transmit(new CommandAPDU(0x00,0x25,0x52,0x00,response.getData()));
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
    public static ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<String>  initCommands) throws CardException {
        if (initCommands != null) {
            for (String cmd : initCommands) {
                cardMngr.getChannel().transmit(new CommandAPDU(Util.hexStringToByteArray(cmd)));
            }
        }

        final ResponseAPDU resp = cardMngr.getChannel().transmit(new CommandAPDU(Util.hexStringToByteArray(command)));
        return resp;
    }
 }