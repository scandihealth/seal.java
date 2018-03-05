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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/security/CryptoFacadeException.java $
 * $Id: CryptoFacadeException.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.security;

/**
 * @author ${user}
 * @author $$LastChangedBy: ChristianGasser $$
 * @version $$Revision: 20818 $$
 * @since 1.4.2
 */
@Deprecated
public class CryptoFacadeException extends RuntimeException {

	private static final long serialVersionUID = 2848366382977156671L;

	public CryptoFacadeException() {
		super();
	}

	public CryptoFacadeException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public CryptoFacadeException(String message) {
		super(message);
	}

	public CryptoFacadeException(Throwable throwable) {
		super(throwable);
	}
	
	

}
