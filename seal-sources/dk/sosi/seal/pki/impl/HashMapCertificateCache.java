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
package dk.sosi.seal.pki.impl;

import dk.sosi.seal.pki.CertificateCache;
import dk.sosi.seal.pki.PKIException;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * An in-memory CertificateCache implemented in a hashmap
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: ksr@lakeside.dk $
 * @version $Revision: 8000 $
 * @since 2.1
 */
public class HashMapCertificateCache implements CertificateCache {
    private final Map<Category, Map<String, X509Certificate>> caches = new HashMap<Category, Map<String, X509Certificate>>();

    public X509Certificate getCertificate(Category category, String cacheKey) throws PKIException {
        return getCache(category).get(cacheKey);
    }

    public void putCertificate(Category category, String key, X509Certificate certificate) throws PKIException {
        getCache(category).put(key, certificate);
    }

    private Map<String, X509Certificate> getCache(Category category) {
        Map<String, X509Certificate> cache = caches.get(category);
        if (cache == null) {
            cache = new HashMap<String, X509Certificate>();
            caches.put(category, cache);
        }
        return cache;
    }
}
