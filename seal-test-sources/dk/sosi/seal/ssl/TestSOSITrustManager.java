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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/ssl/TestSOSITrustManager.java $
 * $Id: TestSOSITrustManager.java 20409 2014-09-08 11:32:07Z ChristianGasser $
 */
package dk.sosi.seal.ssl;

import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TestSOSITrustManager extends TestCase {

	X509Certificate entrustRoot = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.ENTRUST_ROOT));
    X509Certificate entrustTdcRoot = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.ENTRUSTROOT_TDCROOT));
    X509Certificate tdcRootTdcSSL2 = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.TDCROOT_TDCSSL_2));

    public void testCheckServerTrusted() throws Exception {

		SOSITrustManager manager = new SOSITrustManager();
		manager.addTrustedCertificate(entrustRoot);

        /* Disabled due to expired certificate - SOSITrustManager is currently not used (was used under issuance/renewal of OCES1 certificates)

		try {
			manager.checkServerTrusted(new X509Certificate[]{entrustRoot, entrustTdcRoot, tdcRootTdcSSL2}, "ANY");
		} catch (CertificateException e) {
			fail("chain failed to validate: " + e);
		}

		//Inverted chain
		try {
			manager.checkServerTrusted(new X509Certificate[]{tdcRootTdcSSL2, entrustTdcRoot, entrustRoot}, "ANY");
		} catch (CertificateException e) {
			fail("chain failed to validate: " + e);
		}

		//No root
		try {
			manager.checkServerTrusted(new X509Certificate[]{tdcRootTdcSSL2, entrustTdcRoot}, "ANY");
		} catch (CertificateException e) {
			fail("chain failed to validate: " + e);
		}
		*/


		//No root - not trusted
		try {
			manager.checkServerTrusted(new X509Certificate[]{entrustTdcRoot}, "ANY");
		} catch (CertificateException e) {
			fail("chain failed to validate: " + e);
		}

		//Short chain
		try {
			manager.checkServerTrusted(new X509Certificate[]{entrustRoot}, "ANY");
		} catch (CertificateException e) {
			fail("chain failed to validate: " + e);
		}


		//Bad ordering
		try {
			manager.checkServerTrusted(new X509Certificate[]{entrustTdcRoot, entrustRoot, tdcRootTdcSSL2}, "ANY");
			fail("bad ordering not detected");
		} catch (CertificateException e) {
			//OK
		}

        X509Certificate ocesRoot = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.OCES_CA_CRT));

		//Untrusted root
		try {
			manager.checkServerTrusted(new X509Certificate[]{ocesRoot}, "ANY");
			fail("untrusted root allowed");
		} catch (CertificateException e) {
			//OK
		}


		//Chain does not terminate with root cert


	}

	public void testGetAcceptedIssuer() throws Exception  {
		SOSITrustManager manager = new SOSITrustManager();
		manager.addTrustedCertificate(entrustRoot);

		X509Certificate[] trusted = manager.getAcceptedIssuers();
        X509Certificate newroot = CertificateParser.asCertificate(XmlUtil.fromBase64(CredentialVaultTestUtil.ENTRUST_ROOT));
		assertEquals(trusted[0], newroot);

	}

}
