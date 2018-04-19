package applets;

import applets.Sha3Keccak.double_uint8;

public class Sha3Keccak_r144_c256 extends Sha3Keccak_W16 {

	static Sha3Keccak_r144_c256 p_Instance = null;
	
	public void postInit() {
		sC = new double_uint8[5];
		sB = new double_uint8[25];
		for ( short i = 0 ; i < KECCAK_STATE_SIZE_WORDS;i++)
			state[i] = new double_uint8();
		for ( short i = 0 ; i < 5;i++)
			sC[i] = new double_uint8();
		for ( short i = 0 ; i < 25;i++)
			sB[i] = new double_uint8();
	}
	private Sha3Keccak_r144_c256()
	{
		this.KECCAK_VALUE_W = 16;
		KECCAK_SEC_LEVEL = 128;
		KECCAK_STATE_SIZE_BITS = (short) (25*KECCAK_VALUE_W);
		KECCAK_CAPACITY = (short) (2*KECCAK_SEC_LEVEL);
		//Code is modified to match with standard Keccak implementation of r+c=1600
		KECCAK_RATE = (short)(KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY);
		//KECCAK_RATE = (short) (KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY);

		//KECCAK_RATE = (short) (KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY)
		//KECCAK_RATE = 1344;//(short)(KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY);
		KECCAK_STATE_SIZE_WORDS  = (short) ((short)(KECCAK_STATE_SIZE_BITS+ ((short)(PROCESSOR_WORD-1)))/(PROCESSOR_WORD));
		KECCAK_RATE_SIZE_WORDS =  (short) ((short)(KECCAK_RATE+(short)(PROCESSOR_WORD-1))/(PROCESSOR_WORD));
		state = new double_uint8[KECCAK_STATE_SIZE_WORDS];
		KECCAK_NUMBER_OF_ROUNDS = 20;
		KECCAK_SIZE_BYTES = 32;
	}
	public static Sha3Keccak_r144_c256 getInstance()
	{
		if(p_Instance == null)
			p_Instance = new Sha3Keccak_r144_c256();
		return p_Instance;
	}
}
