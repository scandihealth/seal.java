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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestCommonsLoggingAuditEventHandler.java $
 * $Id: TestCommonsLoggingAuditEventHandler.java 20806 2014-12-17 12:33:55Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.model.Reply;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.pki.testobjects.CredentialVaultAdapter;
import dk.sosi.seal.pki.testobjects.PrintStreamAdapter;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

/**
 * Test cases for the <code>CommonsLoggingAuditEventHandler</code> class.
 * 
 * @author ads
 * @author $LastChangedBy: ChristianGasser $
 * @since 2.0
 */
public class TestCommonsLoggingAuditEventHandler extends TestCase {

    private PrintStreamAdapter err;
    private PrintStreamAdapter out;

    private static final X509Certificate CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(InlinedTestCertificates.USER_CERTIFICATE_IG));

    public void testFederationInitialized() {
        newInstance().onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_FEDERATION_INITIALIZED, new Object[] { new Federation(new Properties(), null) {

            @Override
            protected boolean subjectDistinguishedNameMatches(DistinguishedName subjectDistinguishedName) {
                return false;
            }
        } });

        assertErr("[INFO] AUDIT - Federation initialized: dk.sosi.seal.pki.TestCommonsLoggingAuditEventHandler$1");
    }

    public void testInvalidInfoEvent() {
        newInstance().onInformationalAuditingEvent("Test", null);

        assertErr("[INFO] AUDIT - Unkown event Test");
    }

    public void testInfoCredentialVaultInitializedWithCredentialPair() {
        newInstance().onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED, new Object[] { new CredentialVaultAdapter() {

            public CredentialPair getSystemCredentialPair() throws CredentialVaultException {
                    return new CredentialPair(CERTIFICATE, null);
            }
        } });

        assertErr("[INFO] AUDIT - Credential vault initialized: dk.sosi.seal.pki.TestCommonsLoggingAuditEventHandler$2, key CN=Anders Sørensen + SERIALNUMBER=CVR:25450442-RID:62810708, O=LAKESIDE A/S // CVR:25450442, C=DK");
    }

    public void testInfoCredentialVaultInitializedWithoutCredentialPair() {
        newInstance().onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED, new Object[] { new CredentialVaultAdapter() });

        assertErr("[INFO] AUDIT - Credential vault initialized: dk.sosi.seal.pki.testobjects.CredentialVaultAdapter");
    }

    public void testInfoSosiXMLValidated() {
        newInstance().onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_SOSI_XML_VALIDATED, new Object[] { XmlUtil.createEmptyDocument() });

        assertErr("[INFO] AUDIT - XML validated: <?xml version=\"1.0\" encoding=\"UTF-8\" ?>");
    }

    public void testInfoCertificateValidated() throws IOException {
        newInstance().onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_CERTIFICATE_VALIDATED, new Object[] {CERTIFICATE});

        assertErr("[INFO] AUDIT - Certificate validated: CN=Anders Sørensen + SERIALNUMBER=CVR:25450442-RID:62810708, O=LAKESIDE A/S // CVR:25450442, C=DK");
    }

    public void testInfoFullCrlDownloaded() {
        newInstance().onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_FULL_CRL_DOWNLOADED, new Object[] { "Download URL" });

        assertErr("[INFO] AUDIT - CRL downloaded: Download URL");
    }

    public void testWarnNoRevocationCheck() throws IOException {
        newInstance().onWarningAuditingEvent(AuditEventHandler.EVENT_TYPE_WARNING_NO_REVOCATION_CHECK, new Object[] { CERTIFICATE });

        assertErr("[WARN] AUDIT - Certificate not checked for revocation: CN=Anders Sørensen + SERIALNUMBER=CVR:25450442-RID:62810708, O=LAKESIDE A/S // CVR:25450442, C=DK");
    }

    public void testWarnInvalidArgument() throws IOException {
        newInstance().onWarningAuditingEvent("Test arg", null);

        assertErr("[WARN] AUDIT - Unkown event Test arg");
    }

    public void testErrorDownloadingFullCRL() {
        newInstance().onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_DOWNLOADING_FULL_CRL, new Object[] { "Download url" });

        assertErr("[ERROR] AUDIT - Error downloading full CRL: Download url");
    }

    public void testErrorFullCRLExpired() {
        Date date = new Date();

        newInstance().onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_FULL_CRL_EXPIRED, new Object[] { "Download url", null, date });

        assertErr("[ERROR] AUDIT - CRL expired: Download url expired at " + date.toString());
    }

    public void testErrorPassingSosiXML() {
        newInstance().onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_PARSING_SOSI_XML, new Object[] { XmlUtil.createEmptyDocument() });

        assertErr("[ERROR] AUDIT - Error parsing XML<?xml version=\"1.0\" encoding=\"UTF-8\" ?>");
    }

    public void testErrorValidationgSosiMessage() {
        if (System.getProperty("java.specification.version").equals("1.4")) {
            System.out.println("'testErrorValidatingSosiMessage' disabled on jdk 1.4 due to different xml attribute order in the version of Xalan shipped with the jdk");
            return;
        }
        newInstance().onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_VALIDATING_SOSI_MESSAGE, new Object[] { new Reply(DGWSConstants.VERSION_1_0_1, "request", "flow", "status", null) });

        String str1 = "[ERROR] AUDIT - Error validating SOSI Message<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
                + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:medcom=\"http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:sosi=\"http://www.sosi.dk/sosi/2006/04/sosi-1.0.xsd\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" id=\"Envelope\">"
                + "<soapenv:Header><wsse:Security>" + "<wsu:Timestamp><wsu:Created>";

        int datePartLength = 20;

        String str2 = "</wsu:Created></wsu:Timestamp>" + "</wsse:Security><medcom:Header><medcom:SecurityLevel>1</medcom:SecurityLevel><medcom:Linking>" + "<medcom:FlowID>flow</medcom:FlowID><medcom:MessageID>";

        int sigPartLength = 28;

        String str3 = "</medcom:MessageID>" + "<medcom:InResponseToMessageID>request</medcom:InResponseToMessageID></medcom:Linking><medcom:FlowStatus>status</medcom:FlowStatus>" + "</medcom:Header></soapenv:Header><soapenv:Body/></soapenv:Envelope>";

        assertEquals("Part 1", str1, err.sb.toString().substring(0, str1.length()));
        assertEquals("Part 2", str2, err.sb.toString().substring(str1.length() + datePartLength, str1.length() + datePartLength + str2.length()));
        assertEquals("Part 3", str3, err.sb.toString().substring(str1.length() + datePartLength + str2.length() + sigPartLength));
    }

    public void testErrorValidatingSTSCertificate() throws IOException {
        newInstance().onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_VALIDATING_STS_CERTIFICATE, new Object[] { CERTIFICATE });

        assertErr("[ERROR] AUDIT - Error validating STS certificate: CN=Anders Sørensen + SERIALNUMBER=CVR:25450442-RID:62810708, O=LAKESIDE A/S // CVR:25450442, C=DK");
    }

    public void testErrorValidatingCertificate() throws IOException {
        newInstance().onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_VALIDATING_CERTIFICATE, new Object[] { CERTIFICATE });

        assertErr("[ERROR] AUDIT - Error validating certificate: CN=Anders Sørensen + SERIALNUMBER=CVR:25450442-RID:62810708, O=LAKESIDE A/S // CVR:25450442, C=DK");
    }

    public void testErrorInvalidEvent() {
        newInstance().onErrorAuditingEvent("Test", null);

        assertErr("[ERROR] AUDIT - Unkown event Test");
    }

    protected void setUp() throws Exception {
        System.setOut(out = new PrintStreamAdapter());
        System.setErr(err = new PrintStreamAdapter());
    }

    private void assertErr(String string) {
        assertEquals("", out.sb.toString());
        assertEquals(string, err.sb.toString());
    }

    private CommonsLoggingAuditEventHandler newInstance() {
        LogFactory.releaseAll();
        LogFactory.getFactory().setAttribute("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        out.reset();
        err.reset();
        return new CommonsLoggingAuditEventHandler();
    }
}