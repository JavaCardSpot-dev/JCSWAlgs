package tests;

import applets.TestSWAlgsApplet;
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
public class SimpleAPDU {

    private final static byte SELECT_TESTAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    private static byte TEST_RSAOEAP[] = {(byte) 0xB0, (byte) 0x5A, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static byte TEST_RSAOEAP_PERF_ENCODE[] = {(byte) 0xB0, (byte) 0x5B, (byte) 0x01, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x10};
    private static byte TEST_RSAOEAP_PERF_DECODE[] = {(byte) 0xB0, (byte) 0x5C, (byte) 0x02, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0xff};
    
    static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));        
    }
    
	 public static void main(String[] args) {
        try {
            demoSingleCommand();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
	
	
	
    public static ResponseAPDU  demoSingleCommand() throws Exception {

        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID);

        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // A) If running on physical card
        // runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator
        runCfg.setAppletToSimulate(TestSWAlgsApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator
        runCfg.setbReuploadApplet(true);
        runCfg.setInstallData(new byte[15]);

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(TEST_RSAOEAP));
        //System.out.println(response);
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