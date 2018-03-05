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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/ssl/TestSOSIKeyManager.java $
 * $Id: TestSOSIKeyManager.java 34042 2017-03-13 13:38:28Z ChristianGasser $
 */
package dk.sosi.seal.ssl;

import dk.sosi.seal.vault.CredentialVaultTestUtil;
import junit.framework.TestCase;

import javax.security.auth.x500.X500Principal;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TestSOSIKeyManager extends TestCase {

	private static final String VALID_ALIAS = "certSerial=5818c1a6";
	private SOSIKeyManager manager = new SOSIKeyManager(CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair());
	private Principal ocesstestii;
	
	public void testChooseClientAlias() throws Exception {
		ocesstestii = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate().getIssuerDN();
		Principal bad = new X500Principal("C=DK,O=TDC,CN=TDC OCES CA");
		
		String alias = manager.chooseClientAlias(new String[]{"RSA"}, new Principal[]{ocesstestii}, null);
		
		assertEquals(VALID_ALIAS, alias);
		
		alias = manager.chooseClientAlias(new String[]{"RSA"}, new Principal[]{bad}, null);
		
		assertNull(alias);
	}

	public void testGetCertificateChain() {
		assertNull(manager.getCertificateChain("cn=dummy"));
		
		X509Certificate[] chain = manager.getCertificateChain(VALID_ALIAS);
		assertNotNull(chain);
		
		assertEquals(1, chain.length);
	}

	public void testGetClientAliases() {
		ocesstestii = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate().getIssuerDN();
		Principal bad = new X500Principal("C=DK,O=TDC,CN=TDC OCES CA");
		
		String[] aliases = manager.getClientAliases("RSA", new Principal[]{ocesstestii});
		
		assertEquals(1, aliases.length);
		assertEquals(VALID_ALIAS, aliases[0]);
		
	    aliases = manager.getClientAliases("RSA", new Principal[]{bad});
		
		assertNull(aliases);
	}

	public void testGetPrivateKey() {
		PrivateKey key = manager.getPrivateKey(VALID_ALIAS);
		assertNotNull(key);
		
		key = manager.getPrivateKey("cn=dummy");
		
		assertNull(key);
	}

	public void testGetServerAliases() {
		String[] aliases = manager.getServerAliases("RSA",new Principal[]{ocesstestii});
		assertNull(aliases);
	}

	public void testChooseServerAlias() {
		String alias = manager.chooseServerAlias("RSA",new Principal[]{ocesstestii}, null);
		assertNull(alias);
	}

}
