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

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class TestCertificateInfo {

    @Test
    public void testIsProbableCertificateInfoString() {
        assertTrue(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN=foo},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN=foo},IssuerDN={bar,CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("DN={foo},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SUBJECTDN={foo},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo},Issuer={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo},IssuerDN={},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo},IssuerDN={bar},CertSerial={}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={{}},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo {} bar},IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo},IssuerDN={bar}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("IssuerDN={bar},CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString("SubjectDN={foo} IssuerDN={bar} CertSerial={1234}"));
        assertFalse(CertificateInfo.isProbableCertificateInfoString(""));
        assertFalse(CertificateInfo.isProbableCertificateInfoString(null));
    }

    @Test
    public void testConstructionFromString() {
        CertificateInfo certificateInfo = CertificateInfo.fromString("SubjectDN={C=DK},IssuerDN={C=SE},CertSerial={133445229}");
        assertEquals("DK", certificateInfo.getSubjectDN().getCountry());
        assertEquals("SE", certificateInfo.getIssuerDN().getCountry());
        assertEquals(new BigInteger("133445229"), certificateInfo.getCertificateSerialNumber());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructingFromNullString() {
        CertificateInfo.fromString(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructingFromEmptyString() {
        CertificateInfo.fromString("");
    }

    /*
    @Test
    public void testOces1() {
        CertificateInfo info = new CertificateInfo(CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate());

        assertEquals("CVR:19343634-RID:1165813849809", info.getSubjectDN().getSubjectSerialNumber());
        assertEquals("Mike validMOCES", info.getSubjectDN().getCommonName());
        assertEquals("JERNALDERBYENS VENNER // CVR:19343634", info.getSubjectDN().getOrganization());
        assertEquals("DK", info.getSubjectDN().getCountry());
        assertNull(info.getSubjectDN().getOrganizationalUnit());

        assertNull(info.getIssuerDN().getSubjectSerialNumber());
        assertEquals("TDC OCES Systemtest CA II", info.getIssuerDN().getCommonName());
        assertEquals("TDC", info.getIssuerDN().getOrganization());
        assertEquals("DK", info.getIssuerDN().getCountry());
        assertNull(info.getIssuerDN().getOrganizationalUnit());

        assertEquals(new BigInteger("1077429787"), info.getCertificateSerialNumber());

        CertificateInfo deserializedInfo = CertificateInfo.fromString(info.toString());

        assertEquals(info.getSubjectDN(), deserializedInfo.getSubjectDN());
        assertEquals(info.getIssuerDN(), deserializedInfo.getIssuerDN());
        assertEquals(info.getCertificateSerialNumber(), deserializedInfo.getCertificateSerialNumber());
    }
    */

    @Test
    public void testOces2() {
        CertificateInfo info = new CertificateInfo(CredentialVaultTestUtil.getOCES2CredentialVault().getSystemCredentialPair().getCertificate());

        assertEquals("CVR:29915938-UID:96092106", info.getSubjectDN().getSubjectSerialNumber());
        assertEquals("SIGNATURGRUPPEN A/S - eTL demo", info.getSubjectDN().getCommonName());
        assertEquals("SIGNATURGRUPPEN A/S // CVR:29915938", info.getSubjectDN().getOrganization());
        assertEquals("DK", info.getSubjectDN().getCountry());
        assertNull(info.getSubjectDN().getOrganizationalUnit());

        assertNull(info.getIssuerDN().getSubjectSerialNumber());
        assertEquals("TRUST2408 Systemtest X CA", info.getIssuerDN().getCommonName());
        assertEquals("TRUST2408", info.getIssuerDN().getOrganization());
        assertEquals("DK", info.getIssuerDN().getCountry());
        assertNull(info.getIssuerDN().getOrganizationalUnit());

        assertEquals(new BigInteger("1282730950"), info.getCertificateSerialNumber());

        CertificateInfo deserializedInfo = CertificateInfo.fromString(info.toString());

        assertEquals(info.getSubjectDN(), deserializedInfo.getSubjectDN());
        assertEquals(info.getIssuerDN(), deserializedInfo.getIssuerDN());
        assertEquals(info.getCertificateSerialNumber(), deserializedInfo.getCertificateSerialNumber());
    }

}
