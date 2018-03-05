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

import dk.sosi.seal.vault.CredentialVaultTestUtil;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class FederationCertificateReferenceTest {

    @Test
    public void checkStringConstructionOK() {
        final FederationCertificateReference reference = new FederationCertificateReference("OCES2,CVR:55832218-UID:1163447368627,1077391241");
        assertEquals("OCES2", reference.getOcesVersion());
        assertEquals("CVR:55832218-UID:1163447368627", reference.getSubjectSerialNumber());
        assertEquals("1077391241", reference.getSerialNumber());
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkStringConstructionNull() {
        new FederationCertificateReference((String) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkStringConstructionEmpty() {
        new FederationCertificateReference("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkStringConstructionTooFew() {
        new FederationCertificateReference("OCES2,hallo");
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkStringConstructionTooMany() {
        new FederationCertificateReference("OCES1,CVR:55832218-UID:1163447368627,1077391241,FOO");
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkCertConstructionNull() {
        new FederationCertificateReference((X509Certificate) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkCertConstructionOCES1() {
        X509Certificate certificate = OCESTestCertificationAuthority.OCES_1_TEST_ROOT_CERTIFICATE;
        new FederationCertificateReference(certificate);
    }

    @Test
    public void checkCertConstructionOCES2OK() {
        final X509Certificate certificate = CredentialVaultTestUtil.getOCES2CredentialVault().getSystemCredentialPair().getCertificate();
        final FederationCertificateReference reference = new FederationCertificateReference(certificate);
        assertEquals("OCES2", reference.getOcesVersion());
        assertEquals("CVR:29915938-UID:96092106", reference.getSubjectSerialNumber());
        assertEquals("1282730950", reference.getSerialNumber());
    }

}
