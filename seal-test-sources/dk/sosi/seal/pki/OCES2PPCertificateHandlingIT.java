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
 * $HeadURL$
 * $Id$
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.pki.impl.PropertiesSOSIConfiguration;
import dk.sosi.seal.pki.impl.federationcert.FederationCertificateStoreAdapter;
import dk.sosi.seal.pki.impl.intermediate.IntermediateCertificateStoreAdapter;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.varia.NullAppender;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import static org.junit.Assert.*;

public class OCES2PPCertificateHandlingIT {


    private CertificationAuthority ca;
    private Properties properties;
    private CertificationAuthority allowExpiredCertsCA;

    @Before
    public void setUp() throws Exception {
        BasicConfigurator.configure(new NullAppender());
        properties = SignatureUtil.setupCryptoProviderForJVM();
        ca = createCertificateAuthority(true);
        allowExpiredCertsCA = createCertificateAuthority(false);
    }

    @After
    public void tearDown() throws Exception {
        ca = null;
        allowExpiredCertsCA = null;
        BasicConfigurator.resetConfiguration();
    }

    private CertificationAuthority createCertificateAuthority(final boolean doValidateExpiration) {
        CRLCertificateStatusChecker statusChecker = getCrlCertificateStatusChecker();
        HashMapCertificateCache certificateCache = new HashMapCertificateCache();

        SOSIConfiguration configuration = PropertiesSOSIConfiguration.createWithDefaultOcesTestProperties(properties);
        FederationCertificateResolver federationCertificateResolver = new FederationCertificateStoreAdapter(configuration, certificateCache);

        return new OCESTestCertificationAuthority(configuration, statusChecker, new IntermediateCertificateStoreAdapter(certificateCache), federationCertificateResolver) {

            @Override
            boolean checkDates(X509Certificate certificate) {
                return doValidateExpiration ? super.checkDates(certificate) : true ;
            }

        };

    }

    private CRLCertificateStatusChecker getCrlCertificateStatusChecker() {
        CRLCache crlCache = new InMemoryCRLCache();
        int interval = 300;
        boolean strict = true;
        int timeToLive = 60000;
        OCESCertificateResolver certificateResolver = new OCESCertificateResolver(new HashMapCertificateCache());
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(crlCache, interval, strict, timeToLive, certificateResolver);
        statusChecker.setConnectTimeout(5000);
        statusChecker.setReadTimeout(5000);
        return statusChecker;
    }

    private X509Certificate loadCertificate(String resource) {
        return CredentialVaultTestUtil.loadCertificate(resource, "Test1234");
    }

    @Test
    public void testValidMocesNoCpr() {
        X509Certificate certificate = loadCertificate("oces2/PP/MOCES_gyldig.p12");
        assertTrue(ca.isValid(certificate));
    }

    @Test
    public void testValidMocesWithCpr() {
        X509Certificate certificate = loadCertificate("oces2/PP/MOCES_cpr_gyldig.p12");
        assertTrue(ca.isValid(certificate));
    }

    @Test
    public void testRevokedMoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/MOCES_spaerret.p12");
        assertFalse(ca.isValid(certificate));
    }

    @Test
    public void testExpiredMoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/MOCES_udloebet.p12");
        assertFalse(ca.isValid(certificate));
    }

    @Test
    public void testValidFoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/FOCES_gyldig.p12");
        assertTrue(ca.isValid(certificate));
    }

    @Test
    public void testRevokedFoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/FOCES_spaerret.p12");
        assertFalse(ca.isValid(certificate));
    }

    @Test
    public void testExpiredFoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/FOCES_udloebet.p12");
        assertFalse(ca.isValid(certificate));
    }

    @Test
    public void testValidVoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/VOCES_gyldig.p12");
        assertTrue(ca.isValid(certificate));
    }

    @Test
    public void testRevokedVoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/VOCES_spaerret.p12");
        assertFalse(ca.isValid(certificate));
    }

    @Test
    public void testExpiredVoces() {
        X509Certificate certificate = loadCertificate("oces2/PP/VOCES_udloebet.p12");
        assertFalse(ca.isValid(certificate));
    }

    // --------------- Special cases ----------------------------------------------

    @Test
    public void testValidCertificatesWithDifferentIntermediateCertificates() {
        X509Certificate certificate_1 = loadCertificate("oces2/PP/NSI/NSI-TC01.p12");
        assertTrue(allowExpiredCertsCA.isValid(certificate_1));
        X509Certificate certificate_2 = loadCertificate("oces2/PP/NSI/NSI-TC05.p12");
        assertTrue(allowExpiredCertsCA.isValid(certificate_2));
    }

    @Test
    public void testCertificateWithoutReferenceToIntermediateCertificate() {
        X509Certificate certificate = loadCertificate("oces2/PP/NSI/NSI-TC06.p12");
        try {
            allowExpiredCertsCA.isValid(certificate);
            fail("Missing intermediate certificate");
        } catch (PKIException expected) {
            assertEquals("Invalid certificate - CA Issuers (1.3.6.1.5.5.7.48.2) not found under Authority Information Access.", expected.getMessage());
        }
    }

    @Test
    public void testCertificateWithInvalidReferenceToIntermediateCertificate() {
        X509Certificate certificate = loadCertificate("oces2/PP/NSI/NSI-TC07.p12");
        try {
            allowExpiredCertsCA.isValid(certificate);
            fail("Missing intermediate certificate");
        } catch (PKIException expected) {
            assertTrue(expected.getMessage().contains("Intermediate certificate could not be found"));
        }
    }

    @Test
    public void testCertificateWithReferenceToWrongIntermediateCertificate() {
        X509Certificate certificate = loadCertificate("oces2/PP/NSI/NSI-TC08.p12");
        try {
            allowExpiredCertsCA.isValid(certificate);
            fail("Wrong intermediate certificate");
        } catch (PKIException expected) {
            assertTrue(expected.getMessage().contains("is not a OCES Test certificate"));
        }
    }

    @Test
    public void testCertificateWithValidIntermediateCertificateWhichIsNotIssuedByRoot() {
        X509Certificate certificate = loadCertificate("oces2/PP/NSI/NSI-TC01.p12");
        //Simulate by validating against another CA
        CertificationAuthority productionCA = CertificationAuthorityFactory.create(System.getProperties(), CertificationAuthorityFactory.OCES_CA, getCrlCertificateStatusChecker(), new HashMapCertificateCache());
        try {
            productionCA.isValid(certificate);
        } catch (PKIException expected) {
            assertEquals("Intermediate certificate not issued by OCES Production root certificate", expected.getMessage());
        }
    }

    @Test
    public void testCertificateWithRevokedIntermediateCertificate() {
        X509Certificate certificate = loadCertificate("oces2/PP/FOCES_gyldig.p12");
        //Simulate revoked intermediate certificate
        CertificateStatusChecker statusChecker = new CertificateStatusChecker() {
            public CertificateStatus getRevocationStatus(X509Certificate certificate) throws PKIException {
                if (OCESUtil.isIssuerOf(certificate, OCESTestCertificationAuthority.OCES_2_TEST_ROOT_CERTIFICATE)) {
                    return new CertificateStatus(false, new Date());
                } else {
                    return getCrlCertificateStatusChecker().getRevocationStatus(certificate);
                }
            }
        };

        CertificationAuthority testCA = CertificationAuthorityFactory.create(System.getProperties(), CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, statusChecker, new HashMapCertificateCache());
        try {
            testCA.isValid(certificate);
            fail("Revoked intermediate certificate");
        } catch (PKIException expected) {
            assertTrue(expected.getMessage().contains("Intermediate certificate is revoked"));
        }
    }

}
