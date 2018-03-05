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
package dk.sosi.seal.pki.impl.federationcert;

import dk.sosi.seal.pki.*;
import dk.sosi.seal.pki.internal.remote.LdapCertificateLoader;
import dk.sosi.seal.pki.internal.remote.RemoteCertificateLoader;
import dk.sosi.seal.pki.internal.store.CachingCertificateStore;
import dk.sosi.seal.pki.internal.store.CertificateStore;
import dk.sosi.seal.pki.internal.store.RemoteCertificateStore;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class FederationCertificateStoreAdapter implements FederationCertificateResolver {
    private final Map<String,CertificateStore> storesByOcesVersion = new HashMap<String,CertificateStore>();

    public FederationCertificateStoreAdapter(SOSIConfiguration conf, CertificateCache cache) {
        initCertificateStore(FederationCertificateReference.OCES2_VERSION, conf.getLdapCertificateHostOCES2(), conf.getLdapCertificatePortOCES2(), cache);
    }

    private void initCertificateStore(String ocesVersion, String hostName, int portNumber, CertificateCache cache) {
        RemoteCertificateLoader loader = new LdapCertificateLoader(hostName, portNumber);
        CertificateStore store = new FederationCertificateCachingCertificateStore(loader, cache);
        storesByOcesVersion.put(ocesVersion, store);
    }

    public X509Certificate getFederationCertificate(FederationCertificateReference reference) {
        CertificateStore store = storesByOcesVersion.get(reference.getOcesVersion());
        if (store == null) {
            throw new PKIException("OCES-version " + reference.getOcesVersion() + " is not supported.");
        }
        return store.getCertificate(reference.toString());
    }

    private static class FederationCertificateCachingCertificateStore extends CachingCertificateStore {
        public FederationCertificateCachingCertificateStore(RemoteCertificateLoader oces1Loader, CertificateCache cache) {
            super(new RemoteCertificateStore(oces1Loader), cache, CertificateCache.Category.FederationCert);
        }

        @Override
        protected String getRemoteKey(String cacheKey) {
            return new FederationCertificateReference(cacheKey).getSubjectSerialNumber();
        }

        @Override
        protected void validate(String cacheKey, X509Certificate certificate) throws PKIException {
            final String refSerialNumber = new FederationCertificateReference(cacheKey).getSerialNumber();
            final String certSerialNumber = certificate.getSerialNumber().toString();
            if ( ! refSerialNumber.equals(certSerialNumber)) {
                throw new PKIException("Certificate lookup for reference '" + cacheKey + "' failed. Got certificate with serialnumber '" + certSerialNumber + "'");
            }
        }
    }
}
