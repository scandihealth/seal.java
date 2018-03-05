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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestCertificationAuthorityFactory.java $
 * $Id: TestCertificationAuthorityFactory.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import junit.framework.TestCase;

import java.util.Properties;

public class TestCertificationAuthorityFactory extends TestCase {

    public void testCertificationAuthorityFactory() {
        final Properties properties = new Properties();
        CertificationAuthority res =
                CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA,
                                                     new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
        assertTrue("Expected OCES2TestCertificationAuthority instance", res instanceof OCESTestCertificationAuthority);

        res = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_CA,
                                                   new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());

        assertTrue("Expected OCES2CertificationAuthority instance", res instanceof OCESCertificationAuthority);
    }

    public void testOldProperties() {
        Properties properties = new Properties();
        properties.setProperty("sosi:certificate.checker", "java.lang.Object");

        try {
            CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA,
                                                 new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
            fail("Exception expected");
        } catch (RuntimeException ex) {
            assertEquals("Exception cause", "sosi:certificate.checker - no longer supported", ex.getMessage());
        }
    }
}