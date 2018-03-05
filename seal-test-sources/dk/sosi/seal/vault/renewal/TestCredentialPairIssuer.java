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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/renewal/TestCredentialPairIssuer.java $
 * $Id: TestCredentialPairIssuer.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.PKIException;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.TDCCredentialPairIssuer;
import dk.sosi.seal.vault.renewal.testobjects.HttpsConnectorAdapter;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;

import java.net.URL;
import java.util.Map;
import java.util.Properties;

public class TestCredentialPairIssuer extends TestCase {
	
	private Properties properties = SignatureUtil.setupCryptoProviderForJVM();

	public void testIssuer() throws Exception {
		final String cert = XmlUtil.toBase64(CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate().getEncoded());

		//Wrong number of certs
		TDCCredentialPairIssuer issuer = new TDCCredentialPairIssuer(properties);
		issuer.setHttpsConnector(new HttpsConnectorAdapter() {
			public String post(String message, URL url, Map<String, String> requestProperties) {
				return "<certificates><certificate>" + cert + "</certificate></certificates>";
			}
		});
		
		try {
			issuer.issue("12341234", "12341234", false);
			fail();
		} catch (PKIException e) {
			assertTrue(e.getMessage().indexOf("Wrong number") != -1);
		}

		//OK
		issuer.setHttpsConnector(new HttpsConnectorAdapter() {
			public String post(String message, URL url, Map<String, String> requestProperties) {
				return "<certificates><certificate>" + cert + "</certificate><certificate>" + cert + "</certificate></certificates>";
			}
		});

		CredentialPair pair = issuer.issue("12341234", "12341234", false);
		assertEquals(CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate(), pair.getCertificate());
		

		//Error
		issuer.setHttpsConnector(new HttpsConnectorAdapter() {
			public String post(String message, URL url, Map<String, String> requestProperties) {
				return "<certificate error>FEJL<br>FEJ</certificate error>";
			}
		});

		try {
			issuer.issue("12341234", "12341234", false);
			fail();
		} catch (PKIException e) {
			assertTrue(e.getMessage().indexOf("FEJL") != -1);
		}
		
		//Nada
		issuer.setHttpsConnector(new HttpsConnectorAdapter() {
			public String post(String message, URL url, Map<String, String> requestProperties) {
				return "bad reply";
			}
		});

		try {
			issuer.issue("12341234", "12341234", false);
			fail();
		} catch (PKIException e) {
		}
		
	}
}