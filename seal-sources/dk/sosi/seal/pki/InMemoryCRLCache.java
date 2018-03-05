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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/InMemoryCRLCache.java $
 * $Id: InMemoryCRLCache.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This is a simple in-memory cache to store the mapping from
 * url to CRLInfo.
 * <p/>
 * It is based of the <code>ConcurrentHashMap</code> found in jdk 1.5.
 * <p/>
 * For semantic for the various methods, see <link>CRLCache</link>.
 *
 * @author ht@arosii.dk
 * @since 2.0
 */
public class InMemoryCRLCache implements CRLCache {

    private final ConcurrentHashMap<String, CRLCache.CRLInfo> cache = new ConcurrentHashMap<String, CRLInfo>();

    public CRLInfo get(final String url) {
        return cache.get(url);
    }

    public CRLInfo update(final String url, final X509CRL crl) {
        return update(url, crl == null ? null : new CRLInfo(crl, new Date().getTime()));
    }

    public CRLInfo update(final String url, final CRLInfo crlInfo) {
        if (url == null) {
            throw new IllegalArgumentException("'url' must not be null");
        }
        if (crlInfo == null) {
            cache.remove(url);
            return null;
        }

        cache.put(url, crlInfo);
        return crlInfo;
    }

    public Set<Map.Entry<String, CRLInfo>> entries() {
        return cache.entrySet();
    }

    public void clear() {
        cache.clear();
    }

}
