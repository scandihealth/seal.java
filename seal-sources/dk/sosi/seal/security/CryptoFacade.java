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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/security/CryptoFacade.java $
 * $Id: CryptoFacade.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.security;

import dk.sosi.seal.SOSIFactory;

import java.util.Properties;

/**
 * Facade for handling cryptoprovider specific code.
 * Each functiongroup is contained in a Handler which is instantiated by a property 
 * 
 * @author ${user}
 * @author $$LastChangedBy: ChristianGasser $$
 * @version $$Revision: 20818 $$
 * @since 1.4.2
 */
@Deprecated
public class CryptoFacade { //NOPMD

	public static CertificateRequestHandler getCertificateRequestHandler(Properties properties) {
		String className = properties.getProperty(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOFACADE_CERTIFICATE_REQUEST_HANDLER, SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOFACADE_BC_CERTIFICATE_REQUEST_HANDLER);
		try {
			return (CertificateRequestHandler) Class.forName(className).newInstance();
		} catch (InstantiationException e) {
			throw new CryptoFacadeException(e.getMessage(), e);
		} catch (IllegalAccessException e) {
			throw new CryptoFacadeException(e.getMessage(), e);
		} catch (ClassNotFoundException e) {
			throw new CryptoFacadeException(e.getMessage(), e);
		}
	}

}
