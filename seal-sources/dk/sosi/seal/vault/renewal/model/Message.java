/*
 * The MIT License
 *
 * Original work sponsored and donated by National Board of e-Health (NSI), Denmark (http://www.nsi.dk)
 *
 * Copyright (C) 2011 National Board of e-Health (NSI), Denmark (http://www.nsi.dk)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
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
 *
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/model/Message.java $
 * $Id: Message.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.model;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

@Deprecated
public abstract class Message { //NOPMD
	
	/**
	 * Return the name of the message. 
	 * @return The message name.
	 */
	public abstract String messageName();

	/**
	 * Generic setter method, that uses reflection to call the appropriate setter method
	 * @param fieldName
	 * @param value
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public void setField(String fieldName, Class<?> type, Object value) throws SecurityException, NoSuchMethodException, IllegalArgumentException, IllegalAccessException, InvocationTargetException {
		Method setter = getSetter(fieldName, type, this.getClass());
		setter.invoke(this, new Object[]{value});
	}

	/**
	 * Generic int setter method.
	 * @param fieldName
	 * @param value
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public void setField(String fieldName, int value) throws SecurityException, NoSuchMethodException, IllegalArgumentException, IllegalAccessException, InvocationTargetException {
		Method setter = getSetter(fieldName, Integer.TYPE, this.getClass());
		setter.invoke(this, new Object[]{new Integer(value)});  //NOPMD
	}
	
	private Method getSetter(String fieldName, Class<?> argumentType, Class<?> target) throws SecurityException, NoSuchMethodException {
		String setterName = "set" + fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
		
		return target.getMethod(setterName, new Class[]{argumentType});
	}

}
