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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/tool/TestSeal.java $
 * $Id: TestSeal.java 10393 2012-11-12 12:08:24Z ChristianGasser $
 */

package dk.sosi.seal.tool;

import dk.sosi.seal.MainTester;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.PKIException;
import dk.sosi.seal.vault.ArchivableCredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.TestRenewableFilebasedCredentialVault;
import dk.sosi.seal.vault.renewal.MockCredentialPairRenewer;
import dk.sosi.seal.vault.renewal.testobjects.HttpsConnectorAdapter;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;

import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;


/**
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @version 1.0 Jun 26, 2006
 * @since 1.0
 */
public class TestSeal extends TestCase {
	
	public static final String SEP = System.getProperty("file.separator");
	public static final String TESTVAULT_JAR = System.getProperty("user.home") + SEP + "testvault.jar";


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
			if(!jar.delete()) fail("Failed to delete test vault");
		}

	}
	public void testImportCert() throws Exception {
		File certFile = CredentialVaultTestUtil.saveResourceToTempFile(CredentialVaultTestUtil.TEST_ROOT_CERT_RESOURCE);
		
		PrintStream sout = System.out;

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		String[] args = new String[] { "-importcert", certFile.getAbsolutePath(), "-alias", "mycert2", "-vault",
				TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);

		args = new String[] { "-importcert", certFile.getAbsolutePath(), "-alias", "mycert3", "-vault",
				TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		String res = new String(bos.toByteArray());
		System.setOut(sout);
		
		assertTrue(res.indexOf(" : mycert2 (trusted certificate") != -1);

		//Now remove the alias
		bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		args = new String[] { "-removealias", "-alias", "mycert2", "-vault",
				TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		res = new String(bos.toByteArray());
		System.setOut(sout);
//		System.out.println(res);
		assertFalse(res.indexOf(": mycert2 (trusted certificate") != -1);

	}

	public void testImportPkcs12() throws Exception {
		PrintStream sout = System.out;

		File pfxFile = CredentialVaultTestUtil.saveBytesToTempFile(XmlUtil.fromBase64(CredentialVaultTestUtil.VOCES_EXPIRED_PKCS12));

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		String[] args = new String[] { "-importpkcs12", pfxFile.getAbsolutePath(), "-alias", "mycert2", "-vault", TESTVAULT_JAR,
				"-vaultpwd", "test1234", "-pkcs12pwd", CredentialVaultTestUtil.VOCES_EXPIRED_PKCS12_PWD};
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		String res = new String(bos.toByteArray());
		System.setOut(sout);

		assertTrue(res.indexOf("1 : sosi:alias_system (private key") != -1);

		bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));

		args = new String[] {
				"-renew", 
				"-vault", 
				TESTVAULT_JAR, 
				"-vaultpwd",
				"test1234"
		};

		MockCredentialPairRenewer renewer = new MockCredentialPairRenewer();
		renewer.setRenewalChargeable(false);
		Seal.setCredentialPairRenewer(renewer);
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		res = new String(bos.toByteArray());
		System.setOut(sout);
		
		assertTrue(res.indexOf("1 : sosi:alias_system (private key") != -1);
		assertTrue(res.indexOf("2 : sosi:alias_system_1 (private key") != -1);


		//Test for chargeable certs
		InputStream sin = System.in;
		bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		System.setIn(new ByteArrayInputStream("y\n".getBytes()));

		args = new String[] {
				"-renew", 
				"-vault", 
				TESTVAULT_JAR, 
				"-vaultpwd",
				"test1234"
		};

		renewer.setRenewalChargeable(true);
		Seal.setCredentialPairRenewer(renewer);
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		res = new String(bos.toByteArray());
		System.setOut(sout);
		System.setIn(sin);
		
		assertTrue(res.indexOf(": sosi:alias_system (private key") != -1);
		assertTrue(res.indexOf(": sosi:alias_system_1 (private key") != -1);
		assertTrue(res.indexOf(": sosi:alias_system_2 (private key") != -1);

		//Dont accept renewal
		bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		System.setIn(new ByteArrayInputStream("p\nn\n".getBytes()));

		args = new String[] {
				"-renew", 
				"-vault", 
				TESTVAULT_JAR, 
				"-vaultpwd",
				"test1234"
		};

		renewer.setRenewalChargeable(true);
		Seal.setCredentialPairRenewer(renewer);
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		res = new String(bos.toByteArray());
		System.setOut(sout);
		System.setIn(sin);

		assertTrue(res.indexOf(": sosi:alias_system (private key") != -1);
		assertTrue(res.indexOf(": sosi:alias_system_1 (private key") != -1);
		assertTrue(res.indexOf(": sosi:alias_system_2 (private key") != -1);
		assertFalse(res.indexOf(": sosi:alias_system_3 (private key") != -1);
	}
	
	public void testRenewKeystore() throws Exception {
		//Initialize the keystore on the filesystem
		
		ArchivableCredentialVault vault = TestRenewableFilebasedCredentialVault.getCredentialVault();
		vault.setSystemCredentialPair(CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair());
		
		assertFalse("Failed to create keystore on filesystem", !TestRenewableFilebasedCredentialVault.KEYSTORE_FILE.exists());
		
		String[] args = new String[] {
				"-renew", 
				"-keystore", 
				TestRenewableFilebasedCredentialVault.KEYSTORE_FILE.getAbsolutePath(), 
				"-keystorepwd",
				TestRenewableFilebasedCredentialVault.KEYSTORE_PASSWORD
		};

		MockCredentialPairRenewer renewer = new MockCredentialPairRenewer();
		renewer.setRenewalChargeable(false);
		Seal.setCredentialPairRenewer(renewer);
		Seal.main(args);

		PrintStream sout = System.out;

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		args = new String[] { "-list", "-keystore", TestRenewableFilebasedCredentialVault.KEYSTORE_FILE.toString(), "-keystorepwd", TestRenewableFilebasedCredentialVault.KEYSTORE_PASSWORD};
		Seal.main(args);
		String res = new String(bos.toByteArray());
		System.setOut(sout);

		assertTrue(res.indexOf("1 : sosi:alias_system (private key") != -1);
		assertTrue(res.indexOf("2 : sosi:alias_system_1 (private key") != -1);

		//Inspect keystore directly
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream is = new FileInputStream(TestRenewableFilebasedCredentialVault.KEYSTORE_FILE);
		ks.load(is, TestRenewableFilebasedCredentialVault.KEYSTORE_PASSWORD.toCharArray());
		is.close();
		
		Enumeration<String> aliases = ks.aliases();
		Map<String, Certificate> entries = new HashMap<String, Certificate>();
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if(ks.isKeyEntry(alias)) {
				entries.put(alias, ks.getCertificate(alias));
			}
		}

		assertTrue(entries.containsKey("sosi:alias_system"));
		assertTrue(entries.containsKey("sosi:alias_system_1"));
	}

	public void testIssue() throws Exception {
		assertFalse("TestSeal.testIssue() disabled because of BC dependency", !MainTester.isBCOnClasspath(SignatureUtil.setupCryptoProviderForJVM()));
		
		final String cert = XmlUtil.toBase64(CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate().getEncoded());
		PrintStream sout = System.out;

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		System.setOut(new PrintStream(bos));
		String[] args = new String[] { "-issue", "-referencenumber", "22341234", "-installationcode", "12341234", "-vault", TESTVAULT_JAR,
				"-vaultpwd", "test1234", "-test" };
		Seal.setHttpsConnector(new HttpsConnectorAdapter() {
			public String post(String message, URL url, Map<String,String> requestProperties) {
				if(message.indexOf("REFNO=12341234") != -1) {
					return "<certificates><certificate>" + cert + "</certificate><certificate>" + cert + "</certificate></certificates>";
				} else {
					return "<certificate error>Du har benyttet et forkert referencenummer</certificate error>";
				}
			}
		});
		try {
			Seal.main(args);
		} catch (PKIException e) {
			assertTrue(e.getMessage(), e.getMessage().indexOf("Du har benyttet et forkert referencenummer") != -1);
		}

		args = new String[] { "-issue", "-referencenumber", "12341234", "-installationcode", "12341234", "-vault", TESTVAULT_JAR,
				"-vaultpwd", "test1234", "-test" };
		
		Seal.main(args);

		args = new String[] { "-list", "-vault", TESTVAULT_JAR, "-vaultpwd", "test1234" };
		Seal.main(args);
		String res = new String(bos.toByteArray());
		System.setOut(sout);

		assertTrue(res.indexOf("1 : sosi:alias_system (private key") != -1);

	}
}
