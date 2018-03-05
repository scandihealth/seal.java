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

import dk.sosi.seal.model.dombuilders.IdentityTokenResponseDOMBuilder;
import dk.sosi.seal.modelbuilders.IdentityTokenResponseModelBuilder;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Test;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.util.Date;
import java.util.Properties;
import java.util.Scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public class IdentityTokenResponseTest extends AbstractModelTest {

    private static final Date CREATED = d(-6);
    private static final Date EXPIRES = d(12);

    @Test
    public void testAttributes() throws Exception {
        String xml = getFileContents("OIO WS-Trust response.template");

        IdentityTokenResponseModelBuilder itrmb = new IdentityTokenResponseModelBuilder();
        IdentityTokenResponse itr = itrmb.build(XmlUtil.readXml(new Properties(), xml, false));

        assertEquals("Action", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", itr.getAction());
        assertEquals("Context", "urn:uuid:00000", itr.getContext());
        assertEquals("Created", CREATED, itr.getCreated());
        assertEquals("AppliesTo", "http://fmk-online.dk", itr.getAppliesTo());
        assertEquals("Expires", EXPIRES, itr.getExpires());
        assertEquals("MessageID", "urn:uuid:99999777-0000-0000", itr.getMessageID());
        assertEquals("RelatesTo", "urn:uuid:99999999-0000-0000", itr.getRelatesTo());
        assertEquals("TokenType", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", itr.getTokenType());
        assertNull("SigningCertificate", itr.getSigningCertificate());

        IdentityToken it = itr.getIdentityToken();

        assertEquals("AudienceRestriction", "http://fmk-online.dk", it.getAudienceRestriction());
        assertEquals("AuthorizationCode", EXPECTED_AUTHORIZATIONCODE, it.getAuthorizationCode());
        assertEquals("CPR", EXPECTED_CPR, it.getCpr());
        assertEquals("CvrNumberIdentifier", EXPECTED_CVR, it.getCvrNumberIdentifier());
        assertEquals("Email", EXPECTED_EMAIL, it.getEmail());
        assertEquals("CommonName", EXPECTED_GIVENNAME + " " + EXPECTED_SURNAME, it.getCommonName());
        assertEquals("NotBefore", CREATED, it.getNotBefore());
        assertEquals("NotOnOrAfter", EXPIRES, it.getNotOnOrAfter());
        assertEquals("OrganizationName", EXPECTED_ORGANIZATION, it.getOrganizationName());
        assertEquals("SurName", EXPECTED_SURNAME, it.getSurName());
    }

    @Test
    public void testFault() throws Exception {
        String xml = getFileContents("OIO WS-Trust error response.xml");

        IdentityTokenResponseModelBuilder itrmb = new IdentityTokenResponseModelBuilder();
        IdentityTokenResponse itr = itrmb.build(XmlUtil.readXml(new Properties(), xml, false));

        assertEquals(true, itr.isFault());
        assertEquals("wst:FailedAuthentication", itr.getFaultCode());
        assertEquals("http://sosi.dk/sts", itr.getFaultActor());
        assertEquals("Authentication failed: Token in request signed by untrusted party", itr.getFaultString());
    }

    private String getFileContents(String filename) throws Exception {
        InputStream stream = getClass().getResourceAsStream("/idwsh-examples/" + filename);

        StringBuilder text = new StringBuilder();
        String NL = System.getProperty("line.separator");
        Scanner scanner = new Scanner(stream, "UTF-8");
        try {
            while (scanner.hasNextLine()) {
                text.append(scanner.nextLine() + NL);
            }
        } finally {
            scanner.close();
        }

        String sCreated = XmlUtil.getDateFormat(true).format(CREATED);
        String sExpires = XmlUtil.getDateFormat(true).format(EXPIRES);

        String res = text.toString();
        res = res.replace("%CREATED%", sCreated);
        res = res.replace("%EXPIRES%", sExpires);
        return res;
    }

    @Test
    public void testSignatureTampering() {
        UserIDCard uidc = createUserIDCard();

        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setIssuer("http://pan.certifikat.dk/sts/services/SecurityTokenService");
        itb.setNotBefore(d(-2));
        itb.setNotOnOrAfter(d(6));
        itb.setUserIdCard(uidc);
        itb.requireCertificateAsReference();
        itb.requireOrganizationName();
        itb.requireCvrNumberIdentifier();
        itb.requireCprNumber();

        IdentityTokenResponseDOMBuilder itrb = new IdentityTokenResponseDOMBuilder();
        itrb.setContext("urn:uuid:00000");
        itrb.setIdentityToken(itb.build());
        itrb.setRelatesTo("urn:uuid:99999999-0000-0000");

        Document identityTokenDoc = itrb.build();
        String xml = XmlUtil.node2String(identityTokenDoc);

        xml = xml.replace("http://fmk-online.dk", "http://e-journal.dk");

        IdentityTokenResponseModelBuilder itrmb = new IdentityTokenResponseModelBuilder();
        IdentityTokenResponse itr = itrmb.build(XmlUtil.readXml(new Properties(), xml, false));

        try {
            itr.getIdentityToken().validateSignature(sosiFactory.getFederation());
            fail();
        } catch (ModelException e) {
            assertEquals("Signature on IdentityToken is invalid", e.getMessage());
        }

    }

}