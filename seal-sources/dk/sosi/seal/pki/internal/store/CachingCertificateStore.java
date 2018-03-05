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
import dk.sosi.seal.pki.PKIException;

import java.security.cert.X509Certificate;

/**
 * This is a combination of a CertificateCache and a CertificateStore.
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: ksr@lakeside.dk $
 * @version $Revision: 8000 $
 * @since 2.1
 */
public abstract class CachingCertificateStore implements CertificateStore {
    private final CertificateStore loader;
    private final CertificateCache cache;
    private final CertificateCache.Category category;

    public CachingCertificateStore(CertificateStore loader, CertificateCache cache, CertificateCache.Category category) {
        this.loader = loader;
        this.cache = cache;
        this.category = category;
    }

    /**
     * Fetch the certificate by the supplied key, caching the result.
     */
    public final synchronized X509Certificate getCertificate(String cacheKey) throws PKIException {
        X509Certificate certificate = cache.getCertificate(category, cacheKey);
        if (certificate == null) {
            String remoteKey = getRemoteKey(cacheKey);
            certificate = loader.getCertificate(remoteKey);
            validate(cacheKey, certificate);
            cache.putCertificate(category, cacheKey, certificate);
        }
        return certificate;
    }

    /**
     * Hook to allow for differences in the cache key and the remote key used when looking up certificates in the store
     */
    protected abstract String getRemoteKey(String cacheKey);

    /**
     * Hook to allow validation of the certificate retrieved from the CertificateStore
     *
     *
     * @param cacheKey the key used to cache the certificate
     * @param certificate the retrieved certificate
     *
     * @throws PKIException when validation fails
     */
    protected void validate(String cacheKey, X509Certificate certificate) throws PKIException {
        // do nothing
    }
}
