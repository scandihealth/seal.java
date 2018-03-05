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

package dk.sosi.seal.model;

import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.CredentialVaultSignatureProvider;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.util.ExceptionCauseMatcher;
import dk.sosi.seal.util.ExceptionCauseMessageContainsMatcher;
import dk.sosi.seal.util.SOSITestUtils;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;

import static junit.framework.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLAssertionTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testConstructionFromOIOSamlJavaSample() throws ParseException {

        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/test-oiosamljava-authentication-assertion.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertEquals("pfx426233b1-9ce1-99cd-c755-19988e670e46", assertion.getID());
        assertEquals("http://fmkwebtest.trifork.netic.dk/idp/saml2/idp/metadata.php", assertion.getIssuer());
        assertEquals(XmlUtil.parseZuluDateTime("2012-09-20T10:56:24Z"), assertion.getNotBefore());
        assertEquals(XmlUtil.parseZuluDateTime("2012-09-20T11:01:54Z"), assertion.getNotOnOrAfter());
        assertEquals("2", assertion.getAssuranceLevel());
        assertEquals("Terri Dalsgård", assertion.getCommonName());
        assertEquals("Dalsgård", assertion.getSurName());
        assertEquals("0101584162", assertion.getCpr());
        assertEquals("certifikat@tdc.dk", assertion.getEmail());
        assertEquals("25767535", assertion.getCvrNumberIdentifier());
        assertEquals("TDC TOTALLØSNINGER A/S", assertion.getOrganizationName());
        assertEquals("1118061020235", assertion.getRidNumberIdentifier());
        assertEquals("http://saml.vronding/fmk-gui", assertion.getAudienceRestriction());
        assertEquals(XmlUtil.parseZuluDateTime("2012-09-20T10:56:54Z"), assertion.getUserAuthenticationInstant());
        assertEquals("DK-SAML-2.0", assertion.getSpecVersion());
        assertEquals("CVR:25767535-RID:1118061020234", assertion.getSubjectNameID());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", assertion.getSubjectNameIDFormat());
        assertEquals("http://vronding1:8080/fmk/saml/SAMLAssertionConsumer", assertion.getRecipient());
        X509Certificate userCertificate = assertion.getUserCertificate();
        assertNotNull(userCertificate);
        assertEquals(new DistinguishedName("C=DK,O=TDC TOTALLØSNINGER A/S // CVR:25767535,CN=Test Bruger 1+SERIALNUMBER=CVR:25767535-RID:1118061020232"), new DistinguishedName(userCertificate.getSubjectX500Principal()));
        assertNotNull(assertion.getSigningCertificate());
        try {
            assertion.validateTimestamp();
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token no longer valid"));
        }
    }

    @Test
    public void testConstructionFromNewNemLoginSampleOne() throws ParseException {
        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-1.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertEquals("_30c5ecce-9108-4df2-bee2-2d1358973444", assertion.getID());
        assertEquals("https://saml.test-nemlog-in.dk/", assertion.getIssuer());
        assertEquals(XmlUtil.parseZuluDateTime("2012-07-03T09:40:55.963Z"), assertion.getNotBefore());
        assertEquals(XmlUtil.parseZuluDateTime("2012-07-03T10:40:55.963Z"), assertion.getNotOnOrAfter());
        assertEquals("3", assertion.getAssuranceLevel());
        assertEquals("Søren Test Mors", assertion.getCommonName());
        assertEquals("", assertion.getSurName());
        assertNull(assertion.getCpr());
        assertEquals("soren@signaturgruppen.dk", assertion.getEmail());
        assertEquals("29915938", assertion.getCvrNumberIdentifier());
        assertEquals("SIGNATURGRUPPEN A/S // CVR:29915938", assertion.getOrganizationName());
        assertEquals("soren", assertion.getRidNumberIdentifier());
        assertEquals("https://saml.remote.signaturgruppen.dk", assertion.getAudienceRestriction());
        assertEquals(XmlUtil.parseZuluDateTime("2012-07-03T09:40:46.104Z"), assertion.getUserAuthenticationInstant());
        assertEquals("DK-SAML-2.0", assertion.getSpecVersion());
        assertEquals("C=DK,O=SIGNATURGRUPPEN A/S // CVR:29915938,CN=Søren Test Mors,Serial=CVR:29915938-RID:soren", assertion.getSubjectNameID());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", assertion.getSubjectNameIDFormat());
        assertEquals("https://remote.signaturgruppen.dk/nemlogin/unsecure/logon.ashx", assertion.getRecipient());
        assertEquals("CN=TDC OCES Systemtest CA II, O=TDC, C=DK", assertion.getCertificateIssuer());
        X509Certificate userCertificate = assertion.getUserCertificate();
        assertNotNull(userCertificate);
        assertEquals(new DistinguishedName("C=DK,O=SIGNATURGRUPPEN A/S // CVR:29915938,CN=Søren Test Mors+SERIALNUMBER=CVR:29915938-RID:soren"), new DistinguishedName(userCertificate.getSubjectX500Principal()));
        assertNotNull(assertion.getSigningCertificate());
        try {
            assertion.validateTimestamp();
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token no longer valid"));
        }
    }

    @Test
    public void testConstructionFromNewestNemLoginSampleTwo() throws ParseException {
        String xml = SOSITestUtils.readXMLStreamAndRemoveFormatting(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-2.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), xml, false);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertEquals("_020a271f-be04-4378-84ce-0a3ccae065c1", assertion.getID());
        assertEquals("https://saml.test-nemlog-in.dk/", assertion.getIssuer());
        assertEquals(XmlUtil.parseZuluDateTime("2017-05-30T15:00:02.337Z"), assertion.getNotBefore());
        assertEquals(XmlUtil.parseZuluDateTime("2017-05-30T16:00:02.337Z"), assertion.getNotOnOrAfter());
        assertEquals("3", assertion.getAssuranceLevel());
        assertEquals("Ane Kjær Rasmussen", assertion.getCommonName());
        assertEquals("", assertion.getSurName());
        assertEquals("0310808520", assertion.getCpr());
        assertEquals("anni@lakeside.dk", assertion.getEmail());
        assertEquals("25450442", assertion.getCvrNumberIdentifier());
        assertEquals("LAKESIDE A/S // CVR:25450442", assertion.getOrganizationName());
        assertEquals("76241773", assertion.getRidNumberIdentifier());
        assertEquals("https://saml.sp1.test-nemlog-in.dk/", assertion.getAudienceRestriction());
        assertEquals(XmlUtil.parseZuluDateTime("2017-05-30T15:05:01.916Z"), assertion.getUserAuthenticationInstant());
        assertEquals("DK-SAML-2.0", assertion.getSpecVersion());
        assertEquals("C=DK,O=LAKESIDE A/S // CVR:25450442,CN=Ane Kjær Rasmussen,Serial=CVR:25450442-RID:76241773", assertion.getSubjectNameID());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", assertion.getSubjectNameIDFormat());
        assertEquals("CN=TRUST2408 Systemtest XIX CA, O=TRUST2408, C=DK", assertion.getCertificateIssuer());
        X509Certificate userCertificate = assertion.getUserCertificate();
        assertNotNull(userCertificate);
        assertEquals(new DistinguishedName("C=DK,O=LAKESIDE A/S // CVR:25450442,CN=Ane Kjær Rasmussen,Serial=CVR:25450442-RID:76241773"), new DistinguishedName(userCertificate.getSubjectX500Principal()));
        assertEquals("https://sp1.test-nemlog-in.dk/demo/login.ashx", assertion.getRecipient());
        X509Certificate signingCertificate = assertion.getSigningCertificate();
        assertNotNull(signingCertificate);
        assertTrue(SOSITestUtils.getNewestIdPTrustVault().isTrustedCertificate(signingCertificate));
        assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());
        try {
            assertion.validateTimestamp();
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token no longer valid"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullDocument() {
        new OIOSAMLAssertion(null);
    }

    @Test
    public void testInvalidSample() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Error validating OIOSAMLAssertion");
        expectedException.expect(new ExceptionCauseMatcher(SAXParseException.class));
        expectedException.expect(new ExceptionCauseMessageContainsMatcher("Issuer"));

        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-1.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        Node issuer = document.getDocumentElement().getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ISSUER).item(0);
        issuer.getParentNode().removeChild(issuer);
        new OIOSAMLAssertion(document.getDocumentElement());
    }

    @Test
    public void testInvalidSAMLFragment() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Element is not a SAML assertion");

        Document document = XmlUtil.readXml(System.getProperties(), "<saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>foo</saml:Issuer>", false);
        new OIOSAMLAssertion(document.getDocumentElement());
    }

    @Test
    public void testNonSAMLFragment() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Element is not a SAML assertion");

        Document document = XmlUtil.readXml(System.getProperties(), "<foo/>", false);
        new OIOSAMLAssertion(document.getDocumentElement());
    }

    @Test
    public void testUnsignedAssertion() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("OIOSAMLAssertion is not signed");

        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-2.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        Node signature = document.getDocumentElement().getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE).item(0);
        signature.getParentNode().removeChild(signature);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertion.validateSignatureAndTrust(SOSITestUtils.getOldIdPTrustVault());
    }

    @Test
    public void testWronglySignedAssertion() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("OIOSAMLAssertion element is not referenced by contained signature");


        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-2.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        Node signature = document.getDocumentElement().getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE).item(0);
        signature.getParentNode().removeChild(signature);

        Element firstAttribute = (Element) document.getDocumentElement().getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE).item(0);
        firstAttribute.setAttributeNS(NameSpaces.WSU_SCHEMA, "wsu:id", "foo");
        firstAttribute.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:wsu", NameSpaces.WSU_SCHEMA);

        CredentialVaultSignatureProvider signatureProvider = new CredentialVaultSignatureProvider(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());

        SignatureConfiguration configuration = new SignatureConfiguration(new String[]{"foo"}, "_020a271f-be04-4378-84ce-0a3ccae065c1", null);
        Element issuer = (Element) document.getDocumentElement().getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ISSUER).item(0);
        configuration.setSignatureSiblingNode(issuer.getNextSibling());
        SignatureUtil.sign(signatureProvider, document, configuration);

        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());
    }

    @Test
    public void testBrokenSignature() {
        String xml = SOSITestUtils.readXMLStreamAndRemoveFormatting(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-2.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), xml, false);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());

        xml = xml.replace("Ane Kjær Rasmussen", "Ronnie Romkugle");
        document = XmlUtil.readXml(System.getProperties(), xml, false);
        assertion = new OIOSAMLAssertion(document.getDocumentElement());
        try {
            assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());
            fail();
        } catch (ModelException e) {
            assertEquals("Signature on OIOSAMLAssertion is invalid", e.getMessage());
        }
    }

    @Test
    public void testValidateTimestamp() {
        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/test-oiosamljava-authentication-assertion.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);

        final Date now = new Date();

        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement()) {
            @Override
            public Date getNotBefore() throws ModelException {
                return now;
            }
            @Override
            public Date getNotOnOrAfter() {
                return new Date(now.getTime() + 5 * 60 * 1000);
            }
        };
        assertion.validateTimestamp();
        assertion.validateTimestamp(10);

        assertion = new OIOSAMLAssertion(document.getDocumentElement()) {
            @Override
            public Date getNotBefore() throws ModelException {
                return new Date(now.getTime() + 60 * 1000);
            }
            @Override
            public Date getNotOnOrAfter() {
                return new Date(now.getTime() + 5 * 60 * 1000);
            }
        };
        try {
            assertion.validateTimestamp();
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token is not valid yet"));
        }
        try {
            assertion.validateTimestamp(30);
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token is not valid yet"));
        }
        assertion.validateTimestamp(60);
        assertion.validateTimestamp(300);

        assertion = new OIOSAMLAssertion(document.getDocumentElement()) {
            @Override
            public Date getNotBefore() throws ModelException {
                return new Date(now.getTime() - 5 * 60 * 1000);
            }
            @Override
            public Date getNotOnOrAfter() {
                return now;
            }
        };
        try {
            assertion.validateTimestamp();
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token no longer valid"));
        }
        assertion.validateTimestamp(1);
        assertion.validateTimestamp(120);

        assertion = new OIOSAMLAssertion(document.getDocumentElement()) {
            @Override
            public Date getNotBefore() throws ModelException {
                return new Date(now.getTime() - 5 * 60 * 1000);
            }
            @Override
            public Date getNotOnOrAfter() {
                return new Date(now.getTime() - 60 * 1000);
            }
        };
        try {
            assertion.validateTimestamp();
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token no longer valid"));
        }
        try {
            assertion.validateTimestamp(30);
            fail();
        } catch (ModelException e) {
            assertTrue(e.getMessage().startsWith("OIOSAML token no longer valid"));
        }
        assertion.validateTimestamp(120);

        try {
            assertion.validateTimestamp(-1000);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("'allowedDriftInSeconds' must not be negative!"));
        }
    }

    @Test
    public void testSHA256() {
        String xml = SOSITestUtils.readXMLStreamAndRemoveFormatting(this.getClass().getResourceAsStream("/oiosaml-examples/NemLog-in_sha256_assertion.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), xml, false);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());

        xml = xml.replace("CN=Grete Jørgensen", "CN=Hans Dampf");
        document = XmlUtil.readXml(System.getProperties(), xml, false);
        assertion = new OIOSAMLAssertion(document.getDocumentElement());
        try {
            assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());
            fail();
        } catch (ModelException e) {
            assertEquals("Signature on OIOSAMLAssertion is invalid", e.getMessage());
        }
    }

}
