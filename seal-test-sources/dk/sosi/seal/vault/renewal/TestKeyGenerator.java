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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/renewal/TestKeyGenerator.java $
 * $Id: TestKeyGenerator.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.SOSIFactory;
import junit.framework.TestCase;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPublicKey;

import java.security.PublicKey;
import java.security.Security;
import java.util.Properties;

public class TestKeyGenerator extends TestCase {


	public void testGenerateKeyPair() throws Exception {
		boolean bcAdded = false;
		if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
			bcAdded = true;
		}
		
		Properties props = new Properties();
		props.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_PKCS12, "BC");
		props.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_X509, "BC");
		props.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_RSA, "BC");
		props.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA, "BC");
		
		KeyGenerator kg = new KeyGenerator("12341234", props);
		
		kg.generateKeyPair();
		
		byte[] req = kg.getCertificateRequest();
		assertNotNull(req);
		
		PublicKey pub = kg.getPublicKey();
		
		assertEquals("RSA", pub.getAlgorithm());
		
		PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(kg.getCertificateRequest());
		
		if(pub instanceof JCERSAPublicKey) {
			JCERSAPublicKey rsapub = (JCERSAPublicKey) pub;
			assertEquals(rsapub.getModulus().signum() == -1 ? 1023 : 1024, rsapub.getModulus().bitLength());
		}
//		assertEquals("expected","was");
		
		pub = p10.getPublicKey();
		if(pub instanceof JCERSAPublicKey) {
			JCERSAPublicKey rsapub = (JCERSAPublicKey) pub;
			assertEquals(rsapub.getModulus().signum() == -1 ? 1023 : 1024, rsapub.getModulus().bitLength());
		}
		
		assertTrue(p10.verify());
		
		if(bcAdded) {
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

}
