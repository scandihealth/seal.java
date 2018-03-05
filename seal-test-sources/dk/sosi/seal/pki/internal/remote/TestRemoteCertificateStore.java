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
package dk.sosi.seal.pki.internal.remote;

import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.pki.InlinedTestCertificates;
import dk.sosi.seal.pki.internal.store.RemoteCertificateStore;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class TestRemoteCertificateStore {
    private static final String USER_CERTIFICATE_IG = InlinedTestCertificates.USER_CERTIFICATE_IG;

    @Test
    public void testValidCertificate() {
        RemoteCertificateLoader loader = Mockito.mock(RemoteCertificateLoader.class);
        when(loader.loadCertificate(anyString())).thenReturn(XmlUtil.fromBase64(USER_CERTIFICATE_IG));
        RemoteCertificateStore store = new RemoteCertificateStore(loader);
        X509Certificate cert = store.getCertificate("holger");
        verify(loader).loadCertificate("holger");
        verifyNoMoreInteractions(loader);
        assertNotNull(cert);
    }

    @Test
    public void testMissingCertificate() {
        RemoteCertificateLoader loader = Mockito.mock(RemoteCertificateLoader.class);
        when(loader.loadCertificate(anyString())).thenReturn(new byte[0]);
        RemoteCertificateStore store = new RemoteCertificateStore(loader);

        try {
            store.getCertificate("holger");
            fail();
        } catch (ModelException e) {
            assertEquals("Unable to create certificate from supplied value", e.getMessage());
        }
        verify(loader).loadCertificate("holger");
        verifyNoMoreInteractions(loader);
    }
}
