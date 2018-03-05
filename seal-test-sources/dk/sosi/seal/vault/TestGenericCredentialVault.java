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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/TestGenericCredentialVault.java $
 * $Id: TestGenericCredentialVault.java 20765 2014-12-10 12:59:03Z ChristianGasser $
 */

package dk.sosi.seal.vault;

import dk.sosi.seal.MainTester;
import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.pki.OCESTestHelper;
import dk.sosi.seal.pki.PKITestCA;
import dk.sosi.seal.vault.renewal.KeyGenerator;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class TestGenericCredentialVault extends TestCase {

	
	public void testAddTrustedCertificate() {

		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
        X509Certificate idpCert = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.OCES_CA_CRT));
		assertEquals(new DistinguishedName("C=DK,O=TDC,CN=TDC OCES CA"), new DistinguishedName(idpCert.getSubjectX500Principal()));

		genericCredentialVault.addTrustedCertificate(idpCert, "someAlias");

		assertTrue(genericCredentialVault.isTrustedCertificate(idpCert));
		assertFalse(genericCredentialVault.isTrustedCertificate(null));

        X509Certificate badIdPCert = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.ANOTHER_CERT));
		assertNotNull(badIdPCert);
		assertFalse(genericCredentialVault.isTrustedCertificate(badIdPCert));
	}

	public void testRemoveTrustedCertificate() {

		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
        genericCredentialVault.addTrustedCertificate(
                CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.OCES_CA_CRT)),
					"dummy");

		assertNotNull(genericCredentialVault.getTrustedCertificate("dummy"));

		genericCredentialVault.removeTrustedCertificate("dummy");

		assertNull(genericCredentialVault.getTrustedCertificate("dummy"));
	}

	public void testGetIdPCertificateNeg() {

		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
        X509Certificate idpCert = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.OCES_CA_CRT));
		assertFalse(genericCredentialVault.isTrustedCertificate(idpCert));
	}

	public void testRemoveTrustedCertificateNeg() {

		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
		try {
			genericCredentialVault.removeTrustedCertificate("dummy");
			fail("No trusted certificate installed. Expected exception!");
		} catch (CredentialVaultException e) {
			// OK
		}
	}

	public void testGetKeystore() {

		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
		assertNotNull(genericCredentialVault.getKeyStore());
	}

	public void testNullPassword() throws Exception {

//		GenericCredentialVault genericCredentialVault = new GenericCredentialVault("password");
//		try {
//			genericCredentialVault.setSystemCredentialPair((CredentialPair) null, null);
//			fail("null password should trigger an IllegalArgumentException");
//		} catch (IllegalArgumentException iae) {
//			// OK
//		}
	}

	public void testNullKeyStore() throws Exception {

		try {
			new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), (KeyStore) null, (String) null);
			fail("null keystore should trigger a CredentialVaultException");
		} catch (CredentialVaultException cve) {
			// OK
		}
	}
	
	public void testGetSystemCredentials() throws Exception {
		CredentialVault v = CredentialVaultTestUtil.getVocesCredentialVault();
		
		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
		
		assertNull(genericCredentialVault.getSystemCredentialPair());
		
		genericCredentialVault.setSystemCredentialPair(v.getSystemCredentialPair());
		
		CredentialPair pair = genericCredentialVault.getSystemCredentialPair();
		assertEquals(pair.getCertificate(), v.getSystemCredentialPair().getCertificate());
		
	}

	// BC specifik test - notice the add,remove of BC
	public void testIsTrustedCertificate() throws Exception {
		Properties properties = SignatureUtil.setupCryptoProviderForJVM();
		if(!MainTester.isBCOnClasspath(properties)) {
			System.out.println("TestGenericCertificate.testIsTrustedCertificate() disabled because of BC dependency");
			return;
		}
		boolean bcAdded = MainTester.addBCAsProvider();
		
		String stsSerial = "CVR:99994444-UID:1234123411111";
		PKITestCA ca = new PKITestCA(properties);
		GenericCredentialVault vault = new GenericCredentialVault(properties, "password");
		
		KeyGenerator kg = new KeyGenerator("1", properties);
		//Speed up test
		kg.setKeySize(512);
		kg.generateKeyPair();
		
		X509Certificate systemCert = OCESTestHelper.issueCertificate("cn=SystemCert,o=Test,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());
		CredentialPair systemCredentials = new CredentialPair(systemCert, kg.getPrivateKey());
		vault.setSystemCredentialPair(systemCredentials);
		
		kg.generateKeyPair();
		X509Certificate other = OCESTestHelper.issueCertificate("cn=Other,o=TEST,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());
		
		kg.generateKeyPair();
		X509Certificate sts = OCESTestHelper.issueCertificate("CN=STS+SN=" + stsSerial + ",o=TEST,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());
				
		//Without federation
		assertTrue(vault.isTrustedCertificate(systemCert));
		assertFalse(vault.isTrustedCertificate(other));
		assertFalse(vault.isTrustedCertificate(sts));
		
		//With federation
		assertTrue(vault.isTrustedCertificate(systemCert));
		assertFalse(vault.isTrustedCertificate(other));

		if(bcAdded) {
			Security.removeProvider(SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE);
		}
	}
}
