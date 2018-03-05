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
package dk.sosi.seal.pki.impl.intermediate;

import dk.sosi.seal.pki.CertificateCache;
import dk.sosi.seal.pki.IntermediateCertificateCache;
import dk.sosi.seal.pki.PKIException;
import dk.sosi.seal.pki.internal.remote.HttpCertificateLoader;
import dk.sosi.seal.pki.internal.remote.RemoteCertificateLoader;
import dk.sosi.seal.pki.internal.store.CachingCertificateStore;
import dk.sosi.seal.pki.internal.store.CertificateStore;
import dk.sosi.seal.pki.internal.store.RemoteCertificateStore;

import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * A remote CertificateStore loading and parsing data from an external source
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: ksr@lakeside.dk $
 * @version $Revision: 8000 $
 * @since 2.1
 */
public class IntermediateCertificateStoreAdapter implements IntermediateCertificateCache {
    private final CertificateStore store;

    public IntermediateCertificateStoreAdapter(CertificateCache cache) {
        this(new HttpCertificateLoader(), cache);
    }

    protected IntermediateCertificateStoreAdapter(RemoteCertificateLoader loader, CertificateCache cache) {
        store = new CachingCertificateStore(new RemoteCertificateStore(loader), cache, CertificateCache.Category.IntermediateCert) {
            @Override
            protected String getRemoteKey(String cacheKey) {
                return cacheKey;
            }
        };
    }

    public final synchronized X509Certificate getCertificate(URI uri) throws PKIException {
        return store.getCertificate(uri.toString());
    }
}
