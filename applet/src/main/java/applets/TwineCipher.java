package applets;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
/**
 * The TWINE Cipher implementation
 * @author Alberto-PC
 *
 */
public class TwineCipher extends Cipher implements IConsts {
	
	/**
	 * The 80 bits of cipher twine
	 */
	public static final short MAX_MEMORY_TEMPORARY=32;
	private static  TwineCipher ref_twineCipher_80 = null;
	private  byte[] temp   =  null;
	private  byte[] temp2   =  null;
	private  byte[] temp3   =  null;
	private  byte[] rk 	= null;
	public static TwineCipher m_instance =null;

	//for storing the expanded key

	DESKey cipherKey = null;
	private byte mode;



	private boolean externalAccess;
	private boolean isInitialized = false;
	public static final byte ALG_TWINE = 19;
	private final  byte  [] roundconst = 
		{
				0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28, 0x13, 0x26,
				0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0b,
		};
	private final  short [] shufinv = {1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};
	private final  short [] shuf = { 5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14};
	private final  byte	 [] sbox = {0x0C, 0x00, 0x0F, 0x0A, 0x02, 0x0B, 0x09, 0x05, 0x08, 0x03, 0x0D, 0x07, 0x01, 0x0E, 0x06, 0x04};
	private final  byte	 [] data_enc  = new byte[16];
	// Key size of twine cipher is 80 bits i.e. 10 byte
	public static TwineCipher getInstance()
	{
		if(m_instance == null)
			m_instance = new TwineCipher();
		return m_instance;
	}
	protected TwineCipher()
	{
		temp   =  JCSystem.makeTransientByteArray(MAX_MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT);
		temp2   =  JCSystem.makeTransientByteArray(MAX_MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT);
		temp3   =  JCSystem.makeTransientByteArray(MAX_MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT);
		rk 	= JCSystem.makeTransientByteArray((short) ((short)36*8),JCSystem.CLEAR_ON_DESELECT);


	}
	
	private void expand80Key(byte[] key)
	{
		short len_x = 20;
		short key_size = 10; // bytes
		short iterator = 0,iterator2=0;;
		byte temp_val=-1;
		byte temp_val2=-1,temp_val3=-1,temp_val4=-1;
		short sh=0;
		// reset the array
		Util.arrayFillNonAtomic(temp, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
		
		unrowl80ExpandKey(key);

		
		for ( iterator = 0 ; iterator < 35;iterator ++)
		{
			rk[(short)(iterator * 8 + 0)] = temp[1];
			rk[(short)(iterator * 8 + 1)] = temp[3];
			rk[(short)(iterator * 8 + 2)] = temp[4];
			rk[(short)(iterator * 8 + 3)] = temp[6];
			rk[(short)(iterator * 8 + 4)] = temp[13];
			rk[(short)(iterator * 8 + 5)] = temp[14];
			rk[(short)(iterator * 8 + 6)] = temp[15];
			rk[(short)(iterator * 8 + 7)] = temp[16];
			
			temp[1] ^= sbox[temp[0]];
			temp[4] ^= sbox[temp[16]];
			temp_val = roundconst[iterator];
			temp[7] ^= temp_val >> 3;
			temp[19] ^= temp_val & 7;
			
			temp_val  = temp[0];
			temp_val2 = temp[1];
			temp_val3 = temp[2];
			temp_val4 = temp[3];
			
			for (iterator2 = 0 ; iterator2 < 4;iterator2++)
			{
				sh 					= (short)(iterator2*4);
				temp[sh]  			= temp[(short)(sh+4)];
				temp[(short)(sh+1)] = temp[(short)(sh+5)];
				temp[(short)(sh+2)] = temp[(short)(sh+6)];
				temp[(short)(sh+3)] = temp[(short)(sh+7)];
			}
			
			temp[16]   = temp_val2;
			temp[17]   = temp_val3;
			temp[18]   = temp_val4;
			temp[19]   = temp_val;
		
		}
		rk[(short)(35 * 8 + 0)] = temp[1];	
		rk[(short)(35 * 8 + 1)] = temp[3];	
		rk[(short)(35 * 8 + 2)] = temp[4];	
		rk[(short)(35 * 8 + 3)] = temp[6];	
		rk[(short)(35 * 8 + 4)] = temp[13];	
		rk[(short)(35 * 8 + 5)] = temp[14];	
		rk[(short)(35 * 8 + 6)] = temp[15];	
		rk[(short)(35 * 8 + 7)] = temp[16];	
		
	}


	private byte[] encrypt(byte[] src,byte[] dest,short len_src)
	{
		Util.arrayFillNonAtomic(temp, (short)0, (short)32, IConsts.UNTOUCHED_VALUE); //reset all values 
		                                           // 16 bytes for first part
												  // 16 bytes for next
		short iterator=0,iterator2=0,iterator3=0;
		short START_ITERATOR = 16;
		for( iterator = 0 ; iterator < len_src ; iterator++)
		{
			temp[(short)(2*iterator)] = (byte)((short) (src[iterator] & 0x00FF) >> 4);
			temp[(short)(2*iterator+1)] = (byte)((short) (src[iterator] & 0x00FF) & 0x0F);
		}
			
		for ( iterator = 0 ; iterator < 35 ; iterator ++)
		{
			for ( iterator2 = 0 ; iterator2 < 8 ; iterator2 ++)
			{
				temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)] ^ rk[(short)(iterator*8+iterator2)]]; 
						
			}
			
			for (iterator3 = 0 ; iterator3 < 16;iterator3++)
			{
				temp[(short)(shuf[iterator3]+16)] = temp[(iterator3)];
			}
			Util.arrayCopy(temp, (short)16, temp, (short)0, (short)16);
		}
		iterator = 35;
		for (iterator2 = 0; iterator2 < 8 ;iterator2++)
		{
			temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)]^ rk[(short)(iterator*8+iterator2)]]; 		
		}
		
		for ( iterator = 0 ;iterator < 8 ;iterator++)
		{
			temp[(short)(24+iterator)] = (byte)(temp[(short)(2*iterator)] << 4 | temp[(short)(2*iterator + 1)]);
		}
		Util.arrayCopy(temp, (short)24, dest, (short)0, (short)8);
		return temp; // returns bytes from 24 to 32
	}
	private byte[] decrypt(byte[] src,byte[] dest,short len_src)
	{
		// for this alg len_src is always 8 
		Util.arrayFillNonAtomic(temp, (short)0, (short)32, IConsts.UNTOUCHED_VALUE); //reset all values 
		short iterator=0,iterator2=0,iterator3=0;
		short START_ITERATOR = 16;
		for( iterator = 0 ; iterator < len_src ; iterator++)
		{
			temp[(short)(2*iterator)] = (byte)((short) (src[iterator] & 0x00FF) >> 4);
			temp[(short)(2*iterator+1)] = (byte)((short) (src[iterator] & 0x00FF) & 0x0F);
		}
		
		for ( iterator = 35 ; iterator > 0 ; iterator --)
		{
			for ( iterator2 = 0 ; iterator2 < 8 ; iterator2 ++)
			{
				temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)]^ rk[(short)(iterator*8+iterator2)]];
			}
			
			for (iterator3 = 0 ; iterator3 < 16;iterator3++)
			{
				temp[(short)(shufinv[iterator3]+16)] = temp[(iterator3)];
			}
			Util.arrayCopy(temp, (short)16, temp, (short)0, (short)16);
		}
		//FINAL
		iterator = 0;
		for (iterator2 = 0; iterator2 < 8 ;iterator2++)
		{
			temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)]^ rk[(short)(iterator*8+iterator2)]];
		}
		
		for ( iterator = 0 ;iterator < 8 ;iterator++)
		{
			temp[(short)(24+iterator)] = (byte)(temp[(short)(2*iterator)] << 4 | temp[(short)(2*iterator + 1)]);
		}
		Util.arrayCopy(temp, (short)24, dest, (short)0, (short)8);
		return temp; // returns bytes from 24 to 32 indexes
	}


    private void unrowl80ExpandKey(byte[] key)
    {
		temp[(short)(2*0)] = (byte)((short) (key[0] & 0x00FF) >> 4);
		temp[(short)(2*0 + 1)] = (byte)((short) (key[0] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*1)] = (byte)((short) (key[1] & 0x00FF) >> 4);
		temp[(short)(2*1 + 1)] = (byte)((short) (key[1] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*2)] = (byte)((short) (key[2] & 0x00FF) >> 4);
		temp[(short)(2*2 + 1)] = (byte)((short) (key[2] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*3)] = (byte)((short) (key[3] & 0x00FF) >> 4);
		temp[(short)(2*3 + 1)] = (byte)((short) (key[3] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*4)] = (byte)((short) (key[4] & 0x00FF) >> 4);
		temp[(short)(2*4 + 1)] = (byte)((short) (key[4] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*5)] = (byte)((short) (key[5] & 0x00FF) >> 4);
		temp[(short)(2*5 + 1)] = (byte)((short) (key[5] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*6)] = (byte)((short) (key[6] & 0x00FF) >> 4);
		temp[(short)(2*6 + 1)] = (byte)((short) (key[6] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*7)] = (byte)((short) (key[7] & 0x00FF) >> 4);
		temp[(short)(2*7 + 1)] = (byte)((short) (key[7] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*8)] = (byte)((short) (key[8] & 0x00FF) >> 4);
		temp[(short)(2*8 + 1)] = (byte)((short) (key[8] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*9)] = (byte)((short) (key[9] & 0x00FF) >> 4);
		temp[(short)(2*9 + 1)] = (byte)((short) (key[9] & 0x00FF) & 0x0F); 	
    }

	public short doFinal(byte[] inBuff, short inOffset, short inLength,
						 byte[] outBuff, short outOffset) throws CryptoException {
		//not initialized
		if(!isInitialized)
		{
			throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
		}
		if(inLength!=8)
		{
			throw new CryptoException(CryptoException.ILLEGAL_USE);
		}
		if(mode==Cipher.MODE_ENCRYPT)
		{
			cipherKey.getKey(temp2,(short)0);
			expand80Key(temp2);
			Util.arrayFillNonAtomic(temp2,(short)0,MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayCopy(inBuff,inOffset,temp3,(short)0,inLength);
			encrypt(temp3,temp2,inLength);
			Util.arrayCopy(temp2, (short)0, outBuff, outOffset, (short)8);
			//cleaning of sensitive memory
			Util.arrayFillNonAtomic(temp, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayFillNonAtomic(temp2, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayFillNonAtomic(temp3, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayFillNonAtomic(rk, (short)0, (short)(36*8) , (byte) 0x00);

			return (short)8;
		}
		else //decrypt
		{
			cipherKey.getKey(temp2,(short)0);
			expand80Key(temp2);
			Util.arrayCopy(inBuff,inOffset,temp3,(short)0,inLength);
			decrypt(temp3,temp2,inLength);
			Util.arrayCopy(temp2, (short)0, outBuff, outOffset, (short)8);
			//cleaning of sensitive memory
			Util.arrayFillNonAtomic(temp, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayFillNonAtomic(temp2, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayFillNonAtomic(temp3, (short)0, MAX_MEMORY_TEMPORARY, (byte) 0x00);
			Util.arrayFillNonAtomic(rk, (short)0, (short)(36*8) , (byte) 0x00);

			return (short)8;
		}
	}
	public byte getAlgorithm()
	{
		return ALG_TWINE;
	}
	//initkey is a deskey of length 16
	//only the 10 bytes of the key is used by the algorithm
	public void init(Key initkey, byte mode) throws CryptoException
	{
		if(!initkey.isInitialized())
		{
			throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
		}
		if(initkey.getSize()!=128 || initkey.getType()!= KeyBuilder.TYPE_DES)
		{
			throw new CryptoException(CryptoException.ILLEGAL_VALUE);
		}
		this.mode =mode;
		cipherKey = (DESKey)initkey;
		isInitialized=true;
	}

	//not using this mode of init
	//always throw exception
	public void init(Key key, byte mode, byte[] buf, short bOff, short bLen) throws CryptoException
	{
		throw new CryptoException(CryptoException.INVALID_INIT);
	}

	//always throw crypto exception
	//not using this function
	public short update(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws CryptoException {
		throw new CryptoException(CryptoException.ILLEGAL_USE);
	}

}
