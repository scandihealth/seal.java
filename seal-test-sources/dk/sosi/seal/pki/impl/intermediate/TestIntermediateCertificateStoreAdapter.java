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

import dk.sosi.seal.pki.IntermediateCertificateCache;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.pki.internal.remote.RemoteCertificateLoader;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import junit.framework.TestCase;

import java.net.URI;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class TestIntermediateCertificateStoreAdapter extends TestCase {

    public void testCache() throws Exception {
        byte[] testCert = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate().getEncoded();
        RemoteCertificateLoader remoteLoader = mock(RemoteCertificateLoader.class);
        when(remoteLoader.loadCertificate(anyString())).thenReturn(testCert);

        IntermediateCertificateCache cache = new IntermediateCertificateStoreAdapter(remoteLoader, new HashMapCertificateCache());

        cache.getCertificate(new URI("file://foo.bar"));
        verify(remoteLoader).loadCertificate("file://foo.bar");

        cache.getCertificate(new URI("file://foo.bar"));
        verify(remoteLoader).loadCertificate("file://foo.bar");
    }
}