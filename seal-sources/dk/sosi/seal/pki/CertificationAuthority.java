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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/CertificationAuthority.java $
 * $Id: CertificationAuthority.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import java.security.cert.X509Certificate;

/**
 * Class representing a certification authority.
 *
 * @author ads@lakeside.dk
 * @author $LastChangedBy: chg@lakeside.dk $
 * @version $Revision: 8697 $
 * @since 2.0
 */
public interface CertificationAuthority extends FederationCertificateResolver {

    /**
     * Perform revocation check of the passed certificate using the configured CertificateStatusChecker
     *
     * @param certificate
     * @return true if the passed certificate is issued by this CA and is not revoked and is within its validity period. false otherwise
     * @throws PKIException
     *             if the revocation check fails and no <code>CertificateStatusCheckErrorHandler</code> is configured.
     */
    boolean isValid(X509Certificate certificate) throws PKIException;

    /**
     * Perform revocation check of the passed certificate using the configured CertificateStatusChecker.
     *
     *
     * @param certificate to be checked
     * @return a <code>CertificateStatus</code> for the supplied certificate.
     * @throws PKIException
     *             if the revocation check fails and no <code>CertificateStatusCheckErrorHandler</code> is configured.
     */
    CertificateStatus getCertificateStatus(X509Certificate certificate) throws PKIException;

}