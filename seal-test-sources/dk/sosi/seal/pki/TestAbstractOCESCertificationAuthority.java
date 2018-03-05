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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestAbstractOCESCertificationAuthority.java $
 * $Id: TestAbstractOCESCertificationAuthority.java 21233 2015-05-04 10:44:52Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.MainTester;
import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.modelbuilders.SignatureInvalidModelBuildException;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.varia.NullAppender;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

public class TestAbstractOCESCertificationAuthority extends TestCase {

    private Properties properties;
    private boolean bcAdded;

    protected void setUp() throws Exception {
        BasicConfigurator.configure(new NullAppender());
        bcAdded = MainTester.addBCAsProvider();
        super.setUp();
        properties = SignatureUtil.setupCryptoProviderForJVM();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        if(bcAdded) {
            MainTester.removeBCAsProvider();
        }
        BasicConfigurator.resetConfiguration();
    }

    
    public void testExpiredOCES1ProductionCertificate() {
        CertificationAuthority testCA = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        CertificationAuthority prodCA = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        X509Certificate cert = CertificateParser.asCertificate(XmlUtil.fromBase64(InlinedTestCertificates.OCES_1_PRODUCTION_CERT));
        assertFalse(testCA.isValid(cert));
        assertFalse(prodCA.isValid(cert));
    }

    public void testOCES1ProductionRootCertificate() {
        CertificationAuthority testCA = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        CertificationAuthority prodCA = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        X509Certificate cert = OCESCertificationAuthority.OCES_1_ROOT_CERTIFICATE;

        try {
            testCA.isValid(cert);
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Exception cause", "The supplied certificate  with DN 'CN=TDC OCES CA, O=TDC, C=DK' is not a OCES Test certificate", ex.getMessage());
        }

        try {
            prodCA.isValid(cert);
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Exception cause", "The supplied certificate with DN 'CN=TDC OCES CA, O=TDC, C=DK' is an OCES1 certificate. OCES1 certificates are no longer supported.", ex.getMessage());
        }
    }

    public void testOCES1TestRootCertificate() {
        CertificationAuthority testCA = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        CertificationAuthority prodCA = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        X509Certificate cert = OCESTestCertificationAuthority.OCES_1_TEST_ROOT_CERTIFICATE;

        try {
            testCA.isValid(cert);
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Exception cause", "The supplied certificate with DN 'CN=TDC OCES Systemtest CA II, O=TDC, C=DK' is an OCES1 certificate. OCES1 certificates are no longer supported.", ex.getMessage());
        }

        try {
            prodCA.isValid(cert);
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Exception cause", "The supplied certificate  with DN 'CN=TDC OCES Systemtest CA II, O=TDC, C=DK' is not a OCES Production certificate", ex.getMessage());
        }

    }

    public void testOCES2CertificateValidationIG() throws Exception {
        AbstractOCESCertificationAuthority ca = (AbstractOCESCertificationAuthority) CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), getCertificateCacheForIG());
        X509Certificate cert = loadMoces2CertificateIG();
        // Trust to IG removed
        try {
            ca.getAndValidateIntermediateCertificate(cert);
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Exception cause", "Intermediate certificate not issued by OCES Test root certificate", ex.getMessage());
        }
    }

    public void testOCES2CertificateValidationPP() throws Exception {
        CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVault());
        X509Certificate cert = CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate();
        assertTrue(ca.isValid(cert));
    }

    public void testNegativeCheckerUserCertificate() throws IOException {
        CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new MockCertificateStatusChecker(1), CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVault());
        X509Certificate cert = CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate();
        assertFalse(ca.isValid(cert));
    }

    public void testNegativeCheckerIntermediateCertificate() throws IOException {
        CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new MockCertificateStatusChecker(0), CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVault());
        X509Certificate cert = CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate();
        try {

            ca.isValid(cert);
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Exception cause", "Intermediate certificate is revoked", ex.getMessage());
        }
    }

    public void testRetractedIntermediateCertificate() throws PKIException, IOException {
        PublicKey pub = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate()
                .getPublicKey();
        Date notAfter = new Date(System.currentTimeMillis() - 1 * 60 * 1000);
        Date notBefore = new Date(System.currentTimeMillis() - 10 * 60 * 1000);
        final X509Certificate intermediateCertificate = OCESTestHelper.issueCertificate("cn=Thomas,o=Test,c=DK",
            "thomas@signaturgruppen.dk", pub, loadIntermediateCertificatePP().getPublicKey(), notBefore, notAfter);

        final CertificateCache mockCache = new CertificateCache() {
            public void putCertificate(Category category, String key, X509Certificate certificate) throws PKIException {
            }

            public X509Certificate getCertificate(Category category, String key) throws PKIException {
                return intermediateCertificate;
            }
        };
        CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new MockCertificateStatusChecker(0), mockCache);

        try {
            ca.isValid(loadMoces2CertificatePP());
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Dates invalid", "Intermediate certificate not valid in time", ex.getMessage());
        }
    }

    public void testInvalidUserCertificates() throws PKIException, IOException {
        AbstractOCESCertificationAuthority ca = (AbstractOCESCertificationAuthority) CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());

        try {
            // Intermediate certificates don't have an AIA extension at all
            ca.isValid(loadIntermediateCertificatePP());
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Cause", "Invalid certificate - Authority Information Access (1.3.6.1.5.5.7.1.1) not found.",
                    ex.getMessage());
        }

        try {
            // Certificate has an AIA extension but is missing the 'CA Issuers' part
            ca.getAndValidateIntermediateCertificate(loadInvalidMoces2CertificateIG());
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Cause", "Invalid certificate - CA Issuers (1.3.6.1.5.5.7.48.2) not found under Authority Information Access.",
                    ex.getMessage());
        }
    }

    public void testInvalidIntermediateCertificate() throws PKIException, IOException {
        PublicKey pub = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate()
                .getPublicKey();
        final X509Certificate intermediateCertificate = OCESTestHelper.issueCertificate("cn=Thomas,o=Test,c=DK",
            "thomas@signaturgruppen.dk", pub, loadIntermediateCertificatePP().getPublicKey());

        final CertificateCache mockCache = new CertificateCache() {

            public void putCertificate(Category category, String key, X509Certificate certificate) throws PKIException {
            }

            public X509Certificate getCertificate(Category category, String key) throws PKIException {
                return intermediateCertificate;
            }
        };
        CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new MockCertificateStatusChecker(0), mockCache);

        try {
            ca.isValid(loadMoces2CertificatePP());
            fail("Exception expected");
        } catch (PKIException ex) {
            assertEquals("Dates invalid", "Intermediate certificate not issued by OCES Test root certificate", ex.getMessage());
        }
    }

    public void testSOSIFactoryWithOCES2Certificate() throws Exception {
        // Client side!!!
        SOSIFactory clientFactory = CredentialVaultTestUtil.createOCES2SOSIFactory();

        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "12345", "someOrg");
        IDCard clientIdCard = clientFactory.createNewSystemIDCard("SOSITEST", careProvider,
                AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, clientFactory.getCredentialVault()
                        .getSystemCredentialPair().getCertificate(), null);

        // Create request
        Request clientRequest = clientFactory.createNewRequest(true, "oces2testflow");
        clientRequest.setIDCard(clientIdCard);

        // Make request document.
        Document clientDocument = clientRequest.serialize2DOMDocument(XmlUtil.createEmptyDocument());

        // Assert signature of client document
        Node signature = clientDocument.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature").item(0);
        assertNotNull("Signature expected not null", signature);
        assertTrue(SignatureUtil.validate(signature, clientFactory.getFederation(), clientFactory.getCredentialVault(),
                true));

        // Serialize document to XML string
        String clientDocumentXMLString = XmlUtil.node2String(clientDocument);

        // Server side!!!
        SOSIFactory serverFactory = CredentialVaultTestUtil.createOCES2SOSIFactory();
        Request serverRequest = serverFactory.deserializeRequest(clientDocumentXMLString);

        IDCard serverIdCard = serverRequest.getIDCard();
        assertEquals(clientIdCard, serverIdCard);

        clientDocumentXMLString = clientDocumentXMLString.replaceAll("1\\.0\\.1", "1.0");
        try {
            serverFactory.deserializeRequest(clientDocumentXMLString);
            fail("Expected SignatureInvalidModelBuildException");
        } catch (SignatureInvalidModelBuildException e) {
            assertEquals("Signature could not be validated", e.getMessage());
        }
    }

    public void testRootCertificates() {
        AbstractOCESCertificationAuthority ocesCa =
                (AbstractOCESCertificationAuthority) CertificationAuthorityFactory.create
                        (properties, CertificationAuthorityFactory.OCES_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        assertEquals(new DistinguishedName("C=DK,O=TDC,CN=TDC OCES CA"), new DistinguishedName(ocesCa.getOCES1RootCertificate().getSubjectX500Principal()));
        assertEquals(new DistinguishedName("C=DK,O=TRUST2408,CN=TRUST2408 OCES Primary CA"), new DistinguishedName(ocesCa.getOCES2RootCertificate().getSubjectX500Principal()));

        AbstractOCESCertificationAuthority ocesTestCa =
                (AbstractOCESCertificationAuthority) CertificationAuthorityFactory.create
                        (properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        assertEquals(new DistinguishedName("C=DK,O=TDC,CN=TDC OCES Systemtest CA II"), new DistinguishedName(ocesTestCa.getOCES1RootCertificate().getSubjectX500Principal()));
        assertEquals(new DistinguishedName("C=DK,O=TRUST2408,CN=TRUST2408 Systemtest VII Primary CA"), new DistinguishedName(ocesTestCa.getOCES2RootCertificate().getSubjectX500Principal()));
    }

    private static X509Certificate loadMoces2CertificateIG() throws IOException {
        return CredentialVaultTestUtil.loadCertificate("oces2/IG/tc01-valid-moces-cpr1.pkcs12", "Test1234");
    }

    private static CertificateCache getCertificateCacheForIG() throws IOException {
        CertificateCache certificateCache = new HashMapCertificateCache();
        certificateCache.putCertificate(CertificateCache.Category.IntermediateCert, "http://m.aia.systemtest10.trust2408.com/systemtest10-ca.cer", loadIntermediateCertificateIG());
        return certificateCache;
    }

    /* pp */ static X509Certificate loadInvalidMoces2CertificateIG() throws IOException {
        return CredentialVaultTestUtil.loadCertificate("oces2/IG/tc06-valid-moces-no-intermediatecert.pkcs12", "Test1234");
    }

    private static X509Certificate loadIntermediateCertificateIG() throws IOException {
        return CertificateParser.asCertificate(CredentialVaultTestUtil.readResource("oces2/IG/intermediateCerts/systemtest10-ca.cer"));
    }

    private static X509Certificate loadIntermediateCertificatePP() throws IOException {
        return CertificateParser.asCertificate(CredentialVaultTestUtil.readResource("oces2/PP/intermediateCerts/systemtest8-ca.cer"));
    }

    /* pp */ static X509Certificate loadMoces2CertificatePP() throws IOException {
        return CredentialVaultTestUtil.loadCertificate("oces2/PP/MOCES_gyldig.p12", "Test1234");
    }

}