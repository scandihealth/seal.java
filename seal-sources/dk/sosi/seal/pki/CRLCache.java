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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/CRLCache.java $
 * $Id: CRLCache.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * Cache for CRLs based on the retrieval url.
 * <p/>
 * Any implementation should be thread-safe.
 *
 * @author ht@arosii.dk
 * @since 2.0
 */
public interface CRLCache {

    /**
     * A carrier entity to hold the CRL and associated timestamps.
     */
    public static class CRLInfo {

        private final X509CRL crl;
        private final long lastModified;
        private final long created;

        public CRLInfo(final X509CRL crl, final long lastModified) {
            this.crl = crl;
            this.lastModified = lastModified;
            this.created = new Date().getTime();
        }

        CRLInfo(CRLInfo other) {
            this.crl = other.crl;
            this.lastModified = other.lastModified;
            this.created = other.created;
        }

        /**
         * The actual revocation list.
         */
        public X509CRL getCrl() {
            return crl;
        }

        /**
         * The time for which the latest version is from; should be identical
         * to time when the CRL was created.
         */
        public long getLastModified() {
            return lastModified;
        }

        /**
         * The time (absolute time) this was created, should be updated
         * each time a check is made against the endpoint
         */
        public long getCreated() {
            return created;
        }
    }

    /**
     * Retrieves the CRL information from the cache.
     *
     * @param url the location for the CRL
     * @return the combined information containing the CRL.
     */
    CRLInfo get(String url);

    /**
     * Updates the cache for the url with the supplied CRL.
     * <p/>
     * if crl is null the cache entry for url will be removed.
     *
     * @param url the location of the CRL.
     * @param crl the CRL.
     * @return the combined information saved in the cache.
     */
    CRLInfo update(String url, X509CRL crl);

    /**
     * Update the cache with the info.
     * <p/>
     * if the info is null the cache entry for url will be removed.
     *
     * @param url  the location of the CRL.
     * @param info the cache entry.
     * @return the info supplied.
     */
    CRLInfo update(String url, CRLInfo info);

    /**
     * Returns all entries in the cache. Should not be considered
     * mutable.
     *
     * @return all entries in the cache.
     */
    Set<Map.Entry<String, CRLInfo>> entries();

    /**
     * Clears the cache. No entries should be available after
     * this operation is performed.
     */
    void clear();
}
