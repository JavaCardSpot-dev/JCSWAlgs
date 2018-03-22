package applets;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class TestCase {

	private static final short LENGTH_DATA=128;
	private static final short LENGTH_DATA_SMALL=20;
	private static final short OFFSET_START=0;
	private static TestCase m_Instance=null;
	private byte[] ram_reset1;
	private byte[] ram_reset2;
	private byte[] ram_deselect1;
	private byte[] ram_deselect2;
	private byte[] eeProm1;
	private byte[] eeProm2;
	private TestCase() {
		
		ram_reset1 = JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_RESET);
		ram_deselect1 =  JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_DESELECT);
		eeProm1 = new byte[LENGTH_DATA];
		ram_reset2 = JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_RESET);
		ram_deselect2 =  JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_DESELECT);
		eeProm2 = new byte[LENGTH_DATA];
	}
	public static  TestCase getInstance()
	{
		if(m_Instance == null)
			m_Instance = new TestCase();
		return m_Instance;
	}
	public void runInc()
	{
		short p_length = 16000;
		short p_it=0;
		short x=0;
		for (;p_it != p_length;p_it++)
		{
			x = 0;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 1;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 2;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 3;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 4;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 5;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 6;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 7;
		}
	}
	public void runDec()
	{
		short p_length = 16000;
		short p_it=p_length;
		short x=0;
		for (;p_it != 0;--p_it)
		{
			x = 0;
		}
		for (;p_it != 0;--p_it)
		{
			x = 1;
		}
		for (;p_it != 0;--p_it)
		{
			x = 2;
		}
		for (;p_it != 0;--p_it)
		{
			x = 3;
		}
		for (;p_it != 0;--p_it)
		{
			x = 4;
		}
		for (;p_it != 0;--p_it)
		{
			x = 5;
		}
		for (;p_it != 0;--p_it)
		{
			x = 6;
		}
		for (;p_it != 0;--p_it)
		{
			x = 7;
		}
		
	}
	public void testWriteRamRamDeselect()
	{
		RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM).generateData(ram_deselect1,OFFSET_START,LENGTH_DATA);
		Util.arrayCopy(ram_deselect1,OFFSET_START,ram_deselect2,OFFSET_START, LENGTH_DATA);
	}
	public void testWriteRamRamReset()
	{
		RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM).generateData(ram_reset1,OFFSET_START,LENGTH_DATA);
		Util.arrayCopy(ram_reset1,OFFSET_START,ram_reset2,OFFSET_START, LENGTH_DATA);
	}





	public void testMemory()
	{
		ram_reset1 = JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_RESET);
	}

	
}
