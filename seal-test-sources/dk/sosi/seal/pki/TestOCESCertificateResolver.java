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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestOCESCertificateResolver.java $
 * $Id: TestOCESCertificateResolver.java 20808 2014-12-17 15:08:30Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.intermediate.HashMapIntermediateCertificateCache;
import dk.sosi.seal.vault.ClasspathCredentialVault;
import dk.sosi.seal.vault.renewal.KeyGenerator;
import junit.framework.TestCase;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author $LastChangedBy: ChristianGasser $ $LastChangedDate: 2014-12-17 16:08:30 +0100 (Wed, 17 Dec 2014) $
 * @version $Revision: 20808 $
 */
public class TestOCESCertificateResolver extends TestCase {

    private OCESCertificateResolver resolver;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        final IntermediateCertificateCache cache = new HashMapIntermediateCertificateCache();
        resolver = new OCESCertificateResolver(cache);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        resolver = null;
    }

    public void testNull() {
        try {
            resolver.getIssuingCertificate(null);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            //OK
        }
    }

    public void testOces2RootCertificates() throws IOException {
        assertEquals(OCESTestCertificationAuthority.OCES_2_TEST_ROOT_CERTIFICATE, resolver.getIssuingCertificate(OCESTestCertificationAuthority.OCES_2_TEST_ROOT_CERTIFICATE));
        assertEquals(OCESCertificationAuthority.OCES_2_ROOT_CERTIFICATE, resolver.getIssuingCertificate(OCESCertificationAuthority.OCES_2_ROOT_CERTIFICATE));
    }

    /* Disabled since the test relies on being IP-whitelisted against DanIDs PP environment */
    public void failingtestOces2CertificatePP() throws IOException {
        final X509Certificate mocesCertififcatePP = TestAbstractOCESCertificationAuthority.loadMoces2CertificatePP();
        final X509Certificate intermediateCertificatePP = resolver.getIssuingCertificate(mocesCertififcatePP);
        assertEquals(OCESTestCertificationAuthority.OCES_2_TEST_ROOT_CERTIFICATE, resolver.getIssuingCertificate(intermediateCertificatePP));
    }

    public void testOces2InvalidCertificate() throws IOException {
        //OCES2 cert without reference to intermediate certificate
        try {
            resolver.getIssuingCertificate(TestAbstractOCESCertificationAuthority.loadInvalidMoces2CertificateIG());
            fail("PKIException expected");
        } catch (PKIException e) {
            assertEquals("Invalid certificate - CA Issuers (1.3.6.1.5.5.7.48.2) not found under Authority Information Access.", e.getMessage());
        }
    }

    public void testNonOcesCertificate() throws Exception {
        Properties properties = System.getProperties();
        PKITestCA ca = new PKITestCA(properties);

        KeyGenerator kg = new KeyGenerator("1", properties);
        kg.setKeySize(512);
        kg.generateKeyPair();

        X509Certificate certificate = OCESTestHelper.issueCertificate("cn=TestCert,o=Test,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());

        try {
            resolver.getIssuingCertificate(certificate);
            fail("PKIException expected");
        } catch (PKIException e) {
            String errMsg = e.getMessage();
            assertTrue("Expected error message", errMsg.startsWith("Unable to resolve issuing certificate with DN:"));
        }
    }

    public void testOces1TestCertificate() throws Exception {
        try {
            resolver.getIssuingCertificate(OCESTestCertificationAuthority.OCES_1_TEST_ROOT_CERTIFICATE);
            fail("PKIException expected");
        } catch (PKIException e) {
            assertEquals("The supplied certificate issued by: 'CN=TDC OCES Systemtest CA II,O=TDC,C=DK' is an OCES1 certificate which is no longer supported", e.getMessage());
        }
    }

    public void testOces1ProdCertificate() throws Exception {
        try {
            resolver.getIssuingCertificate(OCESCertificationAuthority.OCES_1_ROOT_CERTIFICATE);
            fail("PKIException expected");
        } catch (PKIException e) {
            assertEquals("The supplied certificate issued by: 'CN=TDC OCES CA,O=TDC,C=DK' is an OCES1 certificate which is no longer supported", e.getMessage());
        }
    }

}
