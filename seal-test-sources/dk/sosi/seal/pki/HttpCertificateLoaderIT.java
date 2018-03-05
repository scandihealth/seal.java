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

import dk.sosi.seal.pki.internal.remote.HttpCertificateLoader;
import dk.sosi.seal.xml.CertificateParser;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.varia.NullAppender;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.net.URISyntaxException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

public class HttpCertificateLoaderIT {

    @Before
    public void setUp() throws Exception {
        BasicConfigurator.configure(new NullAppender());
    }

    @After
    public void tearDown() throws Exception {
        BasicConfigurator.resetConfiguration();
    }

    @Test
    @Ignore
    public void testUnknownHost() throws URISyntaxException {
        HttpCertificateLoader loader = new HttpCertificateLoader();
        try {
            loader.loadCertificate("http://www.unknown.host");
            fail("unknown host");
        } catch (PKIException expected) {
            assertEquals("Intermediate certificate could not be found at http://www.unknown.host", expected.getMessage());
        }
    }

    @Test
    public void testKnownHostReturns404() throws URISyntaxException {
        HttpCertificateLoader loader = new HttpCertificateLoader();
        try {
            loader.loadCertificate("http://www.sosi.dk/foobar");
            fail("unknown host");
        } catch (PKIException expected) {
            assertNull(String.valueOf(expected.getCause()), expected.getCause());
        }
    }

    @Test
    public void testSuccessful() {
        HttpCertificateLoader loader = new HttpCertificateLoader();
        byte[] bytes = loader.loadCertificate("http://v.aia.ica02.trust2408.com/oces-issuing02-ca.cer");
        X509Certificate x509Certificate = CertificateParser.asCertificate(bytes);
        assertNotNull(x509Certificate);
    }
}
