package applets;

public interface IConsts 
{
	/**
	 * System variables
	 */
	public static final byte  UNTOUCHED_VALUE = 0x02;
	public static final byte  TRUE = 0x01;
	public static final byte  FALSE = 0x03;
	public static final byte  OFFSET_START=0x00;
	public static final short INVALID_DATA_LENGTH=-1;
	
	/**
	 * CMD_CLA variables
	 */
	public static final byte OFFSET_CLA_APPLICATION = (byte) 0x00;
	
	public static final byte OFFSET_INS_LIGHT =  (byte) 0x11;
	public static final byte OFFSET_INS_TEST   = (byte) 0x23;
	public static final byte OFFSET_INS_HASH   = (byte) 0x24;
	public static final byte OFFSET_INS_RSAOAEP   = (byte) 0x25;

	public static final byte OFFSET_P1_ENC 	 = (byte) 0x21;
	public static final byte OFFSET_P1_DEC	 = (byte) 0x22;
	public static final byte OFFSET_P1_GEN 	 = (byte) 0x23;
	
	
	
	/***
	 * For Lightweight cryptography
	 */
	public static final byte TWINE_CIPHER_80=0x30;
	public static final byte TWINE_CIPHER_128=0x31;
	public static final byte ZORRO_CIPHER=0x33;
	public static final byte AES_CIPHER=0x32;

	
	public static final byte HASH_KECCAK_160  = 0x40;
	public static final byte HASH_KECCAK_r144c256  = 0x41;
	public static final byte HASH_KECCAK_r128c272 = 0x42;
	public static final byte HASH_KECCAK_r544c256 = 0x43;
	public static final byte HASH_KECCAK_r512c288 = 0x44;
	public static final byte HASH_KECCAK_r256c544 = 0x46;
	public static final byte HASH_SHA512 = 0x47;

	public static final byte RSAOAEP_ENC 	 = (byte) 0x51;
	public static final byte RSAOAEP_DEC	 = (byte) 0x52;
	public static final byte HASH = 0x00;
	
	
	/**
	 *  for test mode
	 */
	public static final byte CMD_TEST_LOOP_INC=(byte) 0x00;
	public static final byte CMD_TEST_LOOP_DEC=(byte) 0x01;
	
	public static final byte CMD_TEST_READ_EEPROM_EEPROM = 0x03;
	public static final byte CMD_TEST_WRITE_EEPROM_EEPROM=0x04;
	
	public static final byte CMD_TEST_READ_RAM_DESELECT=0x05;
	public static final byte CMD_TEST_WRITE_RAM_DESELECT=0x06;
	
	public static final byte CMD_TEST_READ_RAM_RESET=0x07;
	public static final byte CMD_TEST_WRITE_RAM_RESET=0x08;
	
	public static final byte CMD_READ_EEPROM_WRITE_RAM=0x09;
	public static final byte CMD_READ_RAM_WRITE_EEPROM=0x10;
	
	public static final byte CMD_ADD_BIG=0x11;
	public static final byte CMD_MOD_POW_RAM=0x12;
	public static final byte CMD_MOD_POW_EEPROM=0x13;
	
	public static final byte CMD_MOD_MULL_RAM=0x14;
	public static final byte CMD_MOD_MULL_EEPROM=0x15; 
	
	public static final byte CMD_TEST_MEMORY=0x16;
	public static final byte CMD_FULL_TEST_DEBUG=0x17;
	
}
