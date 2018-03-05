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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/CertificationAuthorityFactory.java $
 * $Id: CertificationAuthorityFactory.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.PropertiesSOSIConfiguration;
import dk.sosi.seal.pki.impl.federationcert.FederationCertificateStoreAdapter;
import dk.sosi.seal.pki.impl.intermediate.IntermediateCertificateStoreAdapter;

import java.util.Properties;

/**
 * Factory class for creating <code>CertificationAuthority</code> instances.
 *
 * @author ads@lakeside.dk
 * @author $LastChangedBy: chg@lakeside.dk $
 * @version $Revision: 8697 $
 * @since 2.0
 */
public class CertificationAuthorityFactory {

    /**
     * The string identifying the OCES production CA.
     */
    public static final String OCES_CA = "OCES_CA";

    /**
     * The string identifying the OCES test CA.
     */
    public static final String OCES_SYSTEMTEST_CA = "OCES_SYSTEMTEST_CA";

    /**
     * Create an instance of CertificationAuthority.
     *
     * @param properties                   The initialization <code>Properties</code> of the system
     * @param identifier                   id of the CA to be created
     * @param certificateStatusChecker     <code>CertificateStatusChecker</code> instance used for CRL status check.
     * @param intermediateCertificateCache <code>intermediateCertificateCache</code> instance used for retrieving and caching intermediate certificates.
     * @return new instance of requested CA.
     * @throws PKIException if construction fails.
     * @deprecated Use @link(#create) instead
     */
    @Deprecated
    public static CertificationAuthority createNewCertificationAuthority(Properties properties, String identifier, CertificateStatusChecker certificateStatusChecker, IntermediateCertificateCache intermediateCertificateCache) throws PKIException {
        if (identifier.equals(OCES_CA)) {
            return new OCESCertificationAuthority(properties, certificateStatusChecker, intermediateCertificateCache);
        } else if (identifier.equals(OCES_SYSTEMTEST_CA)) {
            return new OCESTestCertificationAuthority(properties, certificateStatusChecker, intermediateCertificateCache);
        }
        throw new PKIException("Unknown CA identifier: " + identifier);
    }

    /**
     * Create an instance of CertificationAuthority.
     *
     * @param properties               The initialization <code>Properties</code> of the system
     * @param identifier               id of the CA to be created
     * @param certificateStatusChecker <code>CertificateStatusChecker</code> instance used for CRL status check.
     * @param cache                    <code>Cache</code> instance used for retrieving and caching certificates.
     * @return new instance of requested CA.
     * @throws PKIException if construction fails.
     */
    public static CertificationAuthority create(Properties properties, String identifier, CertificateStatusChecker certificateStatusChecker, CertificateCache cache) throws PKIException {
        IntermediateCertificateCache intermediateCertificateStoreAdapter = new IntermediateCertificateStoreAdapter(cache);

        if (identifier.equals(OCES_CA)) {
            SOSIConfiguration configuration = PropertiesSOSIConfiguration.createWithDefaultOcesProperties(properties);
            FederationCertificateResolver federationCertificateResolver = new FederationCertificateStoreAdapter(configuration, cache);
            return new OCESCertificationAuthority(configuration, certificateStatusChecker, intermediateCertificateStoreAdapter, federationCertificateResolver);
        } else if (identifier.equals(OCES_SYSTEMTEST_CA)) {
            SOSIConfiguration configuration = PropertiesSOSIConfiguration.createWithDefaultOcesTestProperties(properties);
            FederationCertificateResolver federationCertificateResolver = new FederationCertificateStoreAdapter(configuration, cache);
            return new OCESTestCertificationAuthority(configuration, certificateStatusChecker, intermediateCertificateStoreAdapter, federationCertificateResolver);
        } else {
            throw new PKIException("Unknown CA identifier: " + identifier);
        }
    }
}