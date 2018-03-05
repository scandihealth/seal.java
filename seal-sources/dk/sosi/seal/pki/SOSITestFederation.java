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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/SOSITestFederation.java $
 * $Id: SOSITestFederation.java 20816 2014-12-18 10:15:53Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.pki.internal.SOSISTSCertificateMatcher;

import java.util.Properties;

/**
 * Implementation of <code>Federation</code> using the test federation defined by OCES Systemtest CA II and
 * the STS test system.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20816 $
 * @since 1.0
 */

public class SOSITestFederation extends Federation {

    private final static String NEW_FOCES_TEST_STS_SUBJECT_NAME_PREFIX = "SOSI Test Federation";

    private final SOSISTSCertificateMatcher matcher;

    @Deprecated
    public SOSITestFederation(Properties properties, IntermediateCertificateCache intermediateCertificateCache) {
        this(properties, intermediateCertificateCache, new NaiveCertificateStatusChecker(properties));
    }

    @Deprecated
    public SOSITestFederation(Properties properties, IntermediateCertificateCache intermediateCertificateCache, CertificateStatusChecker certificateStatusChecker) {
        super(properties, CertificationAuthorityFactory.createNewCertificationAuthority(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, certificateStatusChecker, intermediateCertificateCache));
        matcher = new SOSISTSCertificateMatcher(NEW_FOCES_TEST_STS_SUBJECT_NAME_PREFIX);
    }

    public SOSITestFederation(Properties properties) {
        this(properties, new HashMapCertificateCache());
    }

    public SOSITestFederation(Properties properties, CertificateCache cache) {
        this(properties, cache, new NaiveCertificateStatusChecker(properties));
    }

    public SOSITestFederation(Properties properties, CertificateCache cache, CertificateStatusChecker certificateStatusChecker) {
        super(properties, CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, certificateStatusChecker, cache));
        matcher = new SOSISTSCertificateMatcher(NEW_FOCES_TEST_STS_SUBJECT_NAME_PREFIX);
    }

    @Override
    protected boolean subjectDistinguishedNameMatches(DistinguishedName subjectDistinguishedName) {
        return matcher.matches(subjectDistinguishedName);
    }
}