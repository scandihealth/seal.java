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

import com.unboundid.ldap.sdk.LDAPException;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.xml.CertificateParser;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

public class LdapCertificateLoaderIT {
    private LdapCertificateLoader loader;

    @Before
    public void initLdap() {
        loader = new LdapCertificateLoader("crtdir.certifikat.dk", 389);
    }

    @Test
    @Ignore("Disabled while there are two valid certificates with the same CVR-FID - do be re-enabled when switching SOSI Federation certificates is completed.")
    public void testFindAnSTSProdCertificate() throws LDAPException {
        String subjectSerialNumber = loader.findSubjectSerialNumber("c=DK", "SERIALNUMBER=CVR:33257872-FID:52685834");
        DistinguishedName dn = new DistinguishedName(getCertificate(subjectSerialNumber).getSubjectX500Principal());
        assertEquals("DK", dn.getCountry());
        assertEquals("National Sundheds-IT // CVR:33257872", dn.getOrganization());
        assertEquals("SOSI Federation 1 (funktionscertifikat)", dn.getCommonName());
        assertEquals("CVR:33257872-FID:52685834", dn.getSubjectSerialNumber());
    }

    @Test
    public void testFindDanIDVoces2TestCertificate() throws LDAPException {
        loader = new LdapCertificateLoader("crtdir.pp.certifikat.dk", 389);
        X509Certificate cert = getCertificate("CVR:30808460-UID:25351738");
        assertEquals("1478025777", cert.getSerialNumber().toString());
        DistinguishedName dn = new DistinguishedName(cert.getSubjectX500Principal());
        assertEquals("DK", dn.getCountry());
        assertEquals("NETS DANID A/S // CVR:30808460", dn.getOrganization());
        assertEquals("NETS DANID A/S - TU VOCES gyldig", dn.getCommonName());
        assertEquals("CVR:30808460-UID:25351738", dn.getSubjectSerialNumber());
    }

    private X509Certificate getCertificate(String subjectSerialNumber) throws LDAPException {
        return CertificateParser.asCertificate(loader.bySubjectSerialNumber(subjectSerialNumber));
    }
}
