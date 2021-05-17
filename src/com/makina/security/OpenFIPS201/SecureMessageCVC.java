/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.OpenFIPS201 ;

import javacard.framework.*;

public class SecureMessageCVC  
{
	// Mandatory fields
	// As per SP 800 73-4 4.1.5 (Table 15)
	public static final short TAG_CVC = (short)0x7F21;
	public static final short TAG_CPI = (short)0x5F29;
	public static final short TAG_IIN = (short)0x42;
	public static final short TAG_SI = (short)0x5F20;
	public static final short TAG_CHPK = (short)0x7F49;
	public static final short TAG_CHPK_ALG = (short)0x06;
	public static final short TAG_CHPK_KEY = (short)0x86;
	public static final short TAG_ROLE = (short)0x5F4C;
	public static final short TAG_DSIG = (short)0x5F37;

	
	public SecureMessageCVC() {
		
	}
	
	public void parse(byte[] buffer, short offset) {
		
		
		
	}
	

}
