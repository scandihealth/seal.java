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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/CRLCertificateStatusCheckerIT.java $
 * $Id: CRLCertificateStatusCheckerIT.java 20887 2015-01-15 10:20:38Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.intermediate.HashMapIntermediateCertificateCache;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.renewal.KeyGenerator;
import dk.sosi.seal.xml.CertificateParser;
import junit.framework.TestCase;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.varia.NullAppender;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class CRLCertificateStatusCheckerIT extends TestCase {

    private static final String CRL_URL = "http://crl.oces.trust2408.com/oces.crl";
    private static int INT5MIN = 300;
    private static String VAULT_DEFAULT_PASSWORD = "Test1234";

    private final CRLCache cache = new InMemoryCRLCache();
    protected final int defaultTTL = 5 * 60 * 60 * 1000;

    private static void clearJDKInternalCRLCache() {
        try {
            CertificateFactory.getInstance("X.509").generateCRL(null);
        } catch (CRLException e) {
            // OK: see implementation ... (X509Factory.java)
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    protected CRLCache cache() {
        cache.clear();
        return cache;
    }

    CertificateResolver resolver() {
        return new OCESCertificateResolver(new HashMapIntermediateCertificateCache());
    }

    CRLCertificateStatusChecker checker() {
        return new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, false, defaultTTL, resolver());
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        // Prevent (expected) error messages to be emitted
        BasicConfigurator.configure(new NullAppender());
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        BasicConfigurator.resetConfiguration();
    }

    public void testIllegalArguments() {
        try {
            new CRLCertificateStatusChecker(null, CRLCertificateStatusChecker.ALWAYS, false, defaultTTL, resolver());
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // expected
        }

        try {
            new CRLCertificateStatusChecker(cache(), -100, false, defaultTTL, resolver());
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // expected
        }

        try {
            new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, false, -defaultTTL, null);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // expected
        }

    }

    public void testIsNullRevoked() throws Exception {
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.NEVER, false, defaultTTL, resolver());
        try {
            statusChecker.getRevocationStatus(null);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // OK
        }
    }

    public void testCertificateWithoutCRLRef() throws Exception {

        Properties properties = System.getProperties();
        PKITestCA ca = new PKITestCA(properties);

        KeyGenerator kg = new KeyGenerator("1", properties);
        kg.setKeySize(512);
        kg.generateKeyPair();

        X509Certificate cert = OCESTestHelper.issueCertificate("cn=TestCert,o=Test,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());

        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, false, defaultTTL, resolver());
        statusChecker.getRevocationStatus(cert);

        statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, defaultTTL, resolver());
        try {
            statusChecker.getRevocationStatus(cert);
            fail();
        } catch (IllegalStateException e) {
            // OK
        }

    }

    public void testValidCertificateButUrlUnreachable_Strict() throws Exception {
        final CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), INT5MIN, true, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
                throw new IOException("Artificial Timeout.");
            }
        };

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing01-ca.cer");
        try {
            assertFalse(statusChecker.getRevocationStatus(cert).isValid());
            fail("Strict case should throw exception in case of unreachable CRL URL");
        } catch (IllegalStateException t) {
            // OK
        }
    }

    public void testValidCertificateButUrlUnreachableNonStrict() throws Exception {
        final CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), INT5MIN, false, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
                throw new IOException("Artificial Timeout.");
            }
        };

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing01-ca.cer");
        CertificateStatus revoked = statusChecker.getRevocationStatus(cert);
        assertEquals(revoked.getTimestamp(), CRLCertificateStatusChecker.INVALID_TIMESTAMP);
        assertTrue(revoked.isValid());
    }

    public void testTTL() throws Exception {
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, Integer.MIN_VALUE, resolver());

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing01-ca.cer");
        try {
            statusChecker.getRevocationStatus(cert);
            fail("CRL should not be valid");
        } catch (IllegalStateException e) {
            // OK
        }
    }

    public void testNoTTL() throws Exception {
        final AtomicBoolean loaded = new AtomicBoolean(false);

        // serve the crl, which has next update in the past (2009) for any certificate
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, CRLCertificateStatusChecker.NEVER, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(String url, CRLCache.CRLInfo crlInfo) throws IOException {
                InputStream inStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ocesNextUpdateInPast.crl");

                X509CRL crl;
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    crl = (X509CRL) cf.generateCRL(inStream);
                    assertNotNull(crl);
                    assertTrue(loaded.compareAndSet(false, true));
                } catch (CRLException e) {
                    throw new RuntimeException(e);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } finally {
                    inStream.close();
                }
                return new UncheckedCRLInfo(crl, new Date().getTime());
            }

            @Override
            protected boolean verify(X509CRL crl, X509Certificate cert) {
                return true;
            }
        };

        // doesn't matter which certificate we use
        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing02-ca.cer");
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());
        assertTrue(loaded.get());
    }

    public void testVerificationFailed() throws Exception {
        X509Certificate cert = loadCertificate("oces2/PP/intermediateCerts/systemtest8-ca.cer");

        // serve a totally unrelated crl for the certificate
        final CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), INT5MIN, true, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
                return super.load("http://crl.oces.trust2408.com/oces.crl", crlInfo);
            }
        };

        try {
            statusChecker.getRevocationStatus(cert);
            fail("CRL should not be valid");
        } catch (IllegalStateException e) {
            // OK
        }
    }

    public void testPartitioned() throws Exception {
        final AtomicBoolean loaded = new AtomicBoolean(false);

        // serve the partitioned crl from any certificate
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(String url, CRLCache.CRLInfo crlInfo) throws IOException {
                InputStream inStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("partcrl.crl");

                X509CRL crl;
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    crl = (X509CRL) cf.generateCRL(inStream);
                    assertNotNull(crl);
                    assertTrue(loaded.compareAndSet(false, true));
                } catch (CRLException e) {
                    throw new RuntimeException(e);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } finally {
                    inStream.close();
                }
                return new UncheckedCRLInfo(crl, new Date().getTime());
            }

            @Override
            protected boolean verify(X509CRL crl, X509Certificate cert) {
                return true;
            }
        };

        // doesn't matter which certificate we use (might by when the order of crl checks is taken into account)
        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing02-ca.cer");
        try {
            statusChecker.getRevocationStatus(cert);
            fail("CRL should not be valid");
        } catch (IllegalStateException e) {
            // OK
        }
        assertTrue(loaded.get());
    }

    public void testUpdateAll() {
        final String KEY = "hey";
        CRLCache.CRLInfo crlInfo = new CRLCache.CRLInfo(null, System.currentTimeMillis());

        final CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), INT5MIN, true, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
                assertEquals(KEY, url);
                return crlInfo;
            }
        };

        cache.update(KEY, crlInfo);

        statusChecker.updateAll();

    }

    // -- test download

    public void testInvalidURL() throws Exception {
        try {
            checker().downloadCRL("http://www.google.com", null);
            fail("Invalid url");
        } catch (PKIException e) {
            // OK
        }
    }

    public void testInvalidConnectTimeout() {
        final CRLCertificateStatusChecker checker = checker();
        try {
            checker.setConnectTimeout(-1500);
            fail();
        } catch (IllegalArgumentException e) {
            // OK
        }
        try {
            checker.setConnectTimeout(0);
            fail();
        } catch (IllegalArgumentException e) {
            // OK
        }
    }

    public void testInvalidReadTimeout() {
        final CRLCertificateStatusChecker checker = checker();
        try {
            checker.setReadTimeout(-1500);
            fail();
        } catch (IllegalArgumentException e) {
            // OK
        }
        try {
            checker.setReadTimeout(0);
            fail();
        } catch (IllegalArgumentException e) {
            // OK
        }
    }

    public void testValidCertificate() throws Exception {
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, defaultTTL, resolver());

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing02-ca.cer");
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());
    }

    public void testValidCertificateCheckIntervalSemantic() throws Exception {
        final AtomicInteger i = new AtomicInteger(0);
        final CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), INT5MIN, true, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
                i.incrementAndGet();
                return super.load(url, crlInfo);
            }
        };

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing02-ca.cer");
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());

        assertTrue(statusChecker.getRevocationStatus(cert).isValid());

        assertEquals(i.get(), 1);
    }

    public void testValidCertificateCheckAlways() throws Exception {
        final AtomicInteger i = new AtomicInteger(0);
        final CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, defaultTTL, resolver()) {
            @Override
            protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
                i.incrementAndGet();
                return super.load(url, crlInfo);
            }
        };

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing02-ca.cer");
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());

        assertTrue(statusChecker.getRevocationStatus(cert).isValid());

        assertEquals(i.get(), 2);
    }

    public void testChecksNotDoneTwice() throws Exception {
        final AtomicInteger counter = new AtomicInteger(0);
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, defaultTTL, resolver()) {
            @Override
            protected boolean verify(X509CRL crl, X509Certificate cert) {
                counter.incrementAndGet();
                return super.verify(crl, cert);
            }
        };

        X509Certificate cert = loadCertificate("oces2/PROD/intermediateCerts/oces-issuing02-ca.cer");
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());
        assertTrue(statusChecker.getRevocationStatus(cert).isValid());

        assertEquals(1, counter.get());
    }

    public void testDownload() throws Exception {

        final CRLCertificateStatusChecker checker = checker();
        checker.setConnectTimeout(2 * 60000);
        checker.setReadTimeout(2 * 60000);
        final CRLCache.CRLInfo crlInfo = checker.downloadCRL(CRL_URL, null);

        assertNotNull(crlInfo);
        assertTrue(System.currentTimeMillis() - crlInfo.getCreated() < 2 * 60000L); // 2 minute to download should be enough
        assertNotNull(crlInfo.getCrl());
    }

    /*
         * Test that the download/creation of a new CRL depends on the lastModified flag.
         */
    public void testNoDownloading() throws Exception {
        final CRLCache.CRLInfo crlInfo1 = checker().downloadCRL(CRL_URL, null);
        clearJDKInternalCRLCache();
        final CRLCache.CRLInfo crlInfo2 = checker().downloadCRL(CRL_URL, null);

        assertTrue(crlInfo1.getCrl().equals(crlInfo2.getCrl()));
        assertFalse(crlInfo1.getCrl() == crlInfo2.getCrl());

        clearJDKInternalCRLCache();

        final CRLCache.CRLInfo crlInfo3 = checker().downloadCRL(CRL_URL, crlInfo2);
        assertTrue(crlInfo2.getCrl().equals(crlInfo3.getCrl()));
        assertTrue(crlInfo2.getCrl() == crlInfo3.getCrl());
    }

    public void testRevokedCertificate() throws Exception {
        CRLCertificateStatusChecker statusChecker = new CRLCertificateStatusChecker(cache(), CRLCertificateStatusChecker.ALWAYS, true, defaultTTL, resolver());

        X509Certificate cert = CredentialVaultTestUtil.loadCertificate("oces2/PP/MOCES_spaerret.p12", VAULT_DEFAULT_PASSWORD);
        assertFalse(statusChecker.getRevocationStatus(cert).isValid());
    }

    protected static X509Certificate loadCertificate(String resourceName) {
        byte[] certBytes = CredentialVaultTestUtil.readResource(resourceName);
        return CertificateParser.asCertificate(certBytes);
    }

}
