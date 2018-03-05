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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/TestCredentialVaultTrust.java $
 * $Id: TestCredentialVaultTrust.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.vault;

import junit.framework.TestCase;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class TestCredentialVaultTrust extends TestCase {

	private static final String KEYSTORE_PATH = "TestMOCES2.jks";
	private static final String KEYSTORE_PASSPHRASE = "Test1234";
	private static final String TRUSTED_ALIAS = CredentialVault.ALIAS_SYSTEM;

	public void testClasspathCredentialVault() throws Exception {
		GenericCredentialVault target = new ClasspathCredentialVault(null, KEYSTORE_PATH, KEYSTORE_PASSPHRASE);

		X509Certificate trustedCert = target.getTrustedCertificate(TRUSTED_ALIAS);
		assertNotNull("no trusted cert alias with name " + TRUSTED_ALIAS, trustedCert);

		assertTrue("alias " + TRUSTED_ALIAS + " not trusted", target.isTrustedCertificate(trustedCert));
	}

	public void testFileBasedCredentialVault() throws CredentialVaultException, IOException {
		GenericCredentialVault target = new FileBasedCredentialVault(null, CredentialVaultTestUtil.saveResourceToTempFile("/" + KEYSTORE_PATH), KEYSTORE_PASSPHRASE);

		X509Certificate trustedCert = target.getTrustedCertificate(TRUSTED_ALIAS);
		assertNotNull("no trusted cert alias with name " + TRUSTED_ALIAS, trustedCert);

		assertTrue("alias " + TRUSTED_ALIAS + " not trusted", target.isTrustedCertificate(trustedCert));
	}

	public void testGenericCredentialVault() throws IOException, GeneralSecurityException {
		GenericCredentialVault target = newGenericCredentialVault();

		X509Certificate trustedCert = target.getTrustedCertificate(TRUSTED_ALIAS);
		assertNotNull("no trusted cert alias with name " + TRUSTED_ALIAS, trustedCert);

		assertTrue("alias " + TRUSTED_ALIAS + " not trusted", target.isTrustedCertificate(trustedCert));

		X509Certificate systemCert =  target.getSystemCredentialPair().getCertificate();
		assertNotNull("no system certificate", systemCert);

		assertTrue("system certificate not trusted", target.isTrustedCertificate(systemCert));
	}

	private GenericCredentialVault newGenericCredentialVault() throws IOException, GeneralSecurityException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		BufferedInputStream bis = new BufferedInputStream(TestCredentialVaultTrust.class.getClassLoader().getResourceAsStream(KEYSTORE_PATH));
		try {
			keyStore.load(bis, KEYSTORE_PASSPHRASE.toCharArray());
		} finally {
			bis.close();
		}
		return new GenericCredentialVault(new Properties(), keyStore, KEYSTORE_PASSPHRASE);
	}

}
