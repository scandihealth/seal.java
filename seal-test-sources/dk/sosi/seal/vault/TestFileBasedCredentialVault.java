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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/TestFileBasedCredentialVault.java $
 * $Id: TestFileBasedCredentialVault.java 20765 2014-12-10 12:59:03Z ChristianGasser $
 */
package dk.sosi.seal.vault;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;

import java.io.File;
import java.security.cert.X509Certificate;

/**
 * Test Case for FileBasedCredentialVault.
 * 
 * @author kkj
 * @version 1.0 Apr 22, 2006
 * @since 1.0
 */
public class TestFileBasedCredentialVault extends TestCase {

	public static final String SEP = System.getProperty("file.separator");
	public static final File KEYSTORE_FILE = new File(System.getProperty("user.home") + SEP + "SOSICredentialVault.jks");
	static {
		KEYSTORE_FILE.deleteOnExit();
	}


	public static final String KEYSTORE_PASSWORD = "password";

	public static ArchivableCredentialVault getCredentialVault() throws CredentialVaultException {

		ArchivableCredentialVault credentialVault;
		if (KEYSTORE_FILE.exists()) {
			if(!KEYSTORE_FILE.delete()) fail("Failed to delete existing keystore file");
		}
		
		credentialVault = new FileBasedCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), KEYSTORE_FILE, KEYSTORE_PASSWORD);
		return credentialVault;
	}

	public static String getCertPath() {

		return "src" + SEP + "test" + SEP + "resources";
	}

	public void testCreate() {

		getCredentialVault();

		assertFalse("Keystore was not created!",!KEYSTORE_FILE.exists());
	}

	public void testSetSystemCredentialPair() throws Exception {

		ArchivableCredentialVault credentialVault = getCredentialVault();

		try {
			credentialVault.setSystemCredentialPair(CredentialVaultTestUtil.saveResourceToTempFile(CredentialVaultTestUtil.MOCES_TEST_PFX_RESOURCE), CredentialVaultTestUtil.MOCES_TEST_PFX_PWD);
		} catch (CredentialVaultException e) {
			e.printStackTrace();
			fail("Unable to set system certificate");
		}
	}
	
	public void testPersistence() throws Exception {

		ArchivableCredentialVault credentialVault = getCredentialVault();
		credentialVault.setSystemCredentialPair(CredentialVaultTestUtil.saveResourceToTempFile(CredentialVaultTestUtil.MOCES_TEST_PFX_RESOURCE), CredentialVaultTestUtil.MOCES_TEST_PFX_PWD);

		ArchivableCredentialVault loaded = new FileBasedCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), KEYSTORE_FILE, KEYSTORE_PASSWORD);
		CredentialPair readPair = loaded.getSystemCredentialPair();

		assertEquals(readPair.getCertificate(), credentialVault.getSystemCredentialPair().getCertificate());
		
	}

	public void testAddTrustedCertificate() throws Exception {

		ArchivableCredentialVault credentialVault = getCredentialVault();
		try {
			credentialVault.setSystemCredentialPair(CredentialVaultTestUtil.saveResourceToTempFile(CredentialVaultTestUtil.MOCES_TEST_PFX_RESOURCE), CredentialVaultTestUtil.MOCES_TEST_PFX_PWD);
		} catch (CredentialVaultException e) {
			e.printStackTrace();
			fail("Unable to set system certificate");
		}

        X509Certificate someTrustedCert = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.OCES_CA_CRT));
        assertEquals(new DistinguishedName("C=DK,O=TDC,CN=TDC OCES CA"), new DistinguishedName(someTrustedCert.getSubjectX500Principal()));

		String alias = "certAlias";
		credentialVault.addTrustedCertificate(someTrustedCert, alias);

		assertTrue(credentialVault.isTrustedCertificate(someTrustedCert));
		assertFalse(credentialVault.isTrustedCertificate(null));

        X509Certificate untrustedCert = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.ANOTHER_CERT));
		assertNotNull(untrustedCert);
		assertFalse(credentialVault.isTrustedCertificate(untrustedCert));
	}

	public void testRemoveTrustedCertificate() throws Exception {

		ArchivableCredentialVault credentialVault = getCredentialVault();
		try {
			credentialVault.setSystemCredentialPair(CredentialVaultTestUtil.saveResourceToTempFile(CredentialVaultTestUtil.MOCES_TEST_PFX_RESOURCE), CredentialVaultTestUtil.MOCES_TEST_PFX_PWD);
		} catch (CredentialVaultException e) {
			e.printStackTrace();
			fail("Unable to set system certificate");
		}

        credentialVault.addTrustedCertificate(CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.OCES_CA_CRT)), "dummy");

		assertNotNull(credentialVault.getTrustedCertificate("dummy"));

		credentialVault.removeTrustedCertificate("dummy");

		assertNull(credentialVault.getTrustedCertificate("dummy"));
	}
    
    public void testThreadedAccess() throws InterruptedException {
        new FileBasedCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), KEYSTORE_FILE, KEYSTORE_PASSWORD);
        assertTrue(KEYSTORE_FILE.exists());
        
        int numberOfThreads = 20;
        Thread[] threads = new Thread[numberOfThreads];
        final int[] failures = {0};

        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(new Runnable() {
                public void run() {
                    try {
                        new FileBasedCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), KEYSTORE_FILE, KEYSTORE_PASSWORD);
                    } catch (Exception e) {
                        failures[0]++;
                    }
                }
            });
            threads[i].start();
        }

        for (int i = 0; i < threads.length; i++) {
            threads[i].join();
        }

        assertEquals("Multithreaded access to FileBasedCredentialVault failed", 0, failures[0]);

    }
}
