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
package dk.sosi.seal.pki.internal.store;

import dk.sosi.seal.pki.CertificateCache;
import dk.sosi.seal.pki.InlinedTestCertificates;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class TestHashMapCertificateCache {
    private CertificateCache cache;
    private X509Certificate certificate1;
    private X509Certificate certificate2;

    @Before
    public void setUp() throws Exception {
        cache = new HashMapCertificateCache();
        certificate1 = CertificateParser.asCertificate(XmlUtil.fromBase64(InlinedTestCertificates.USER_CERTIFICATE_IG));
        certificate2 = CertificateParser.asCertificate(XmlUtil.fromBase64(InlinedTestCertificates.USER_CERTIFICATE_WITHOUT_REF_TO_INTERMEDIATE_CERT_IG));
    }

    @Test
    public void testEmptyCache() {
        assertNull(cache.getCertificate(CertificateCache.Category.IntermediateCert, "key"));
    }

    @Test
    public void testEntryCannotBeFoundWithWrongCategory() {
        cache.putCertificate(CertificateCache.Category.IntermediateCert, "key1", certificate1);
        assertNull(cache.getCertificate(CertificateCache.Category.FederationCert, "key1"));
    }

    @Test
    public void testEntryCannotBeFoundWithWrongKey() {
        cache.putCertificate(CertificateCache.Category.IntermediateCert, "key1", certificate1);
        assertNull(cache.getCertificate(CertificateCache.Category.IntermediateCert, "key2"));
    }

    @Test
    public void testEntryFound() {
        cache.putCertificate(CertificateCache.Category.IntermediateCert, "key1", certificate1);
        assertEquals(certificate1, cache.getCertificate(CertificateCache.Category.IntermediateCert, "key1"));
    }

    @Test
    public void testEntriesInSeveralCategories() {
        cache.putCertificate(CertificateCache.Category.IntermediateCert, "key1", certificate1);
        cache.putCertificate(CertificateCache.Category.FederationCert, "key1", certificate2);
        assertEquals(certificate1, cache.getCertificate(CertificateCache.Category.IntermediateCert, "key1"));
        assertEquals(certificate2, cache.getCertificate(CertificateCache.Category.FederationCert, "key1"));
    }

    @Test
    public void testEntriesInSeveralKeys() {
        cache.putCertificate(CertificateCache.Category.IntermediateCert, "key1", certificate1);
        cache.putCertificate(CertificateCache.Category.IntermediateCert, "key2", certificate2);
        assertEquals(certificate1, cache.getCertificate(CertificateCache.Category.IntermediateCert, "key1"));
        assertEquals(certificate2, cache.getCertificate(CertificateCache.Category.IntermediateCert, "key2"));
    }
}
