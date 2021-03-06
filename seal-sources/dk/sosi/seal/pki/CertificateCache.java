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

import java.security.cert.X509Certificate;

/**
 * This is a generic cache of certificates with get/put operations.
 * Note that implementations are NOT expected to be synchronized.
 * You should instead synchronize on the wrapping CachingCertificateStore
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: ksr@lakeside.dk $
 * @version $Revision: 8000 $
 * @since 2.1
 */
public interface CertificateCache {
    enum Category {
        FederationCert, IntermediateCert
    }

    /**
     * Retrieve the cross certificate based on the supplied URL.
     *
     * @param category
     * @param key The remote location of the cross certificate.  @return The cross certificate.
     */
    public void putCertificate(Category category, String key, X509Certificate certificate) throws PKIException;

    /**
     * Retrieve the certificate based on the supplied key.
     *
     * @param category
     * @param key The location of the certificate.
     * @return The certificate.
     */
    public X509Certificate getCertificate(Category category, String key) throws PKIException;
}
