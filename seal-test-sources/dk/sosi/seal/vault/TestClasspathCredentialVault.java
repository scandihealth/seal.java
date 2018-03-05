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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/TestClasspathCredentialVault.java $
 * $Id: TestClasspathCredentialVault.java 10415 2012-11-15 13:25:47Z ChristianGasser $
 */

package dk.sosi.seal.vault;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.tool.Seal;
import junit.framework.TestCase;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.cert.X509Certificate;

/**
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @version 1.0 Jun 26, 2006
 * @since 1.0
 */
public class TestClasspathCredentialVault extends TestCase {

	public static final String SEP = System.getProperty("file.separator");
	public static final String TESTVAULT_JAR = System.getProperty("user.home") + SEP + "cpcredvault.jar";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        deleteTestVault();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        deleteTestVault();
    }

    /**
	 * -importcert <.pkcs12|.cer> -alias &lt;alias> -vault <vault.jar> -vaultpwd
	 * <password> -list -vault <vault.jar> -vaultpwd <password>
	 */
	public static void deleteTestVault() {
		File jar = new File(TESTVAULT_JAR);
		if (jar.exists()) {
			jar.delete();
		}

	}

	/**
	 * Test loading a keystore from the classpath. TODO: it requires a valid
	 * keystore and a correct classpath to setup a positive test. Hence so far
	 * only the negative one exists.
	 */
	public void testCreateNeg() throws Exception {

		try {
			new ClasspathCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "bogus", "test1234");
			fail("Unexpectedly created a credential vault from classpath");
		} catch (CredentialVaultException e) {
			// OK
		}
	}

	public void testReadOnly() throws Exception {

		File certFile = CredentialVaultTestUtil.saveResourceToTempFile(CredentialVaultTestUtil.TEST_ROOT_CERT_RESOURCE);
		PrintStream sout = System.out;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		String[] args = new String[] { "-importcert", certFile.getAbsolutePath(), "-alias", "mycert2", "-vault",
				TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		System.setOut(sout);

		
		MockClassLoader cl = new MockClassLoader(TESTVAULT_JAR);

		ClasspathCredentialVault.setClassLoader(cl);
		ClasspathCredentialVault cv = new ClasspathCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "test1234");
		ClasspathCredentialVault.setClassLoader(null);
		try {
			cv.setSystemCredentialPair(null);
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}
		try {
			cv.setSystemCredentialPair((InputStream) null, null); 
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}
		try {
			cv.setSystemCredentialPair((CredentialPair) null, null);
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}
		try {
			cv.setSystemCredentialPair((File) null, null);
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}

		try {
			cv.addTrustedCertificate((File) null, null); 
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}

		try {
			cv.addTrustedCertificate((X509Certificate) null, null); 
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}

		try {
			cv.removeTrustedCertificate(null); 
			fail("Should fail on write operations");
		} catch (CredentialVaultException cve) {

		}


	}

}
