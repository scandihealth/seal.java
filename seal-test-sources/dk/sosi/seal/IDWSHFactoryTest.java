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
package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.dombuilders.IdentityTokenRequestDOMBuilder;
import dk.sosi.seal.model.dombuilders.IdentityTokenResponseDOMBuilder;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

import java.util.Date;
import java.util.Properties;

import static junit.framework.Assert.*;

/**
 * Test case for testing the flow of the <code>IDWSHFactory</code>.
 * 
 * @author Anders Sørensen/ads@lakeside.dk
 * @since 2.1
 */
public class IDWSHFactoryTest extends AbstractModelTest {

    private static final String ADDRESSING_TO = "http://pan.certifikat.dk/sts/services/SecurityTokenService";
    private static final String AUDIENCE = "http://fmk-online.dk";
    private static IDWSHFactory IDWSH_FACTORY;
    private static final Date NOT_BEFORE = d(-1);
    private static final Date NOT_ON_OR_AFTER = d(2);

    private static final boolean VALIDATE_XML = false;

    @BeforeClass
    public static void setup() {
        IDWSH_FACTORY = new IDWSHFactory(getMockFederation(), sosiFactory.getCredentialVault());
    }

    @Test
    public void flowTest() throws XMLSecurityException {
        // Create the request on the client side
        Document cIdentityTokenRequestDOM = createTestRequestDOM();

        // Transmit the request to the server
        Document sIdentityTokenRequestDOM = assertToXMLandBack(cIdentityTokenRequestDOM);

        // Receive the request on the server
        IdentityTokenRequest sIdentityTokenRequest = createIdentityTokenRequestFromDOM(sIdentityTokenRequestDOM);

        // Create an response on the server.
        Document sIdentityTokenResponseDOM = createIdentityTokenResponseDOMFromRequest(sIdentityTokenRequest);

        // Transmit the response to the client.
        Document cIdentityTokenResponseDOM = assertToXMLandBack(sIdentityTokenResponseDOM);

        // Recieve the response on the client side
        IdentityTokenResponse cIdentityTokenResponse = IDWSH_FACTORY.createIdentityTokenResponseModelBuilder().build(cIdentityTokenResponseDOM);

        // Extract the IdentityToken from the response.
        IdentityToken cIdentityToken = cIdentityTokenResponse.getIdentityToken();

        // JUNIT: Validate IdentityToken
        validateIdentityToken(cIdentityToken);

        // Convert IdentityToken to an URL
        String cURL = cIdentityToken.createURLBuilder().encode();

        IdentityToken uIdentityToken = convertURLtoIdentityToken(cURL);

        // JUNIT: Validate IdentityToken
        validateIdentityToken(uIdentityToken);

        final IDWSHFactory idwshFactoryTrustTestSTS = new IDWSHFactory(new SOSITestFederation(System.getProperties(),
                CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVaultCertInLdap()), null);

        try {
            idwshFactoryTrustTestSTS.createIdentityTokenFromURL(cURL);
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

    }

    private IdentityToken convertURLtoIdentityToken(String url) {
        return IDWSH_FACTORY.createIdentityTokenFromURL(url);
    }

    private void validateIdentityToken(IdentityToken it) {
        assertEquals("Audience", AUDIENCE, it.getAudienceRestriction());
        assertEquals("Authorization Code", EXPECTED_AUTHORIZATIONCODE, it.getAuthorizationCode());
        assertEquals("Common name", EXPECTED_COMMONNAME, it.getCommonName());
        assertEquals("CPR", EXPECTED_CPR, it.getCpr());
        assertEquals("Email", EXPECTED_EMAIL, it.getEmail());
        assertEquals("Not before", NOT_BEFORE, it.getNotBefore());
        assertEquals("Not on or after", NOT_ON_OR_AFTER, it.getNotOnOrAfter());
        assertEquals("Surname", EXPECTED_SURNAME, it.getSurName());
        assertTrue("ID", it.getID().startsWith("_"));
        it.validateSignature(getMockFederation());
    }

    private IdentityTokenBuilder createIdentityTokenBuilder(IdentityTokenRequest request) {
        IdentityTokenBuilder itb = IDWSH_FACTORY.createIdentityTokenBuilder();
        itb.setAudienceRestriction(request.getAudience());
        itb.requireCertificateAsReference();
        itb.setNotBefore(NOT_BEFORE);
        itb.setNotOnOrAfter(NOT_ON_OR_AFTER);
        itb.setUserIdCard((UserIDCard) request.getIDCard());
        itb.requireCprNumber();
        itb.requireUserAuthorizationCode();
        itb.setIssuer("http://pan.certifikat.dk/sts/services/SecurityTokenService");
        return itb;
    }

    private IdentityTokenRequest createIdentityTokenRequestFromDOM(Document sIdentityTokenRequestDOM) {
        return IDWSH_FACTORY.createIdentityTokenRequestModelBuilder().buildModel(sIdentityTokenRequestDOM);
    }

    private Document createIdentityTokenResponseDOMFromRequest(IdentityTokenRequest request) {
        IdentityTokenResponseDOMBuilder b = IDWSH_FACTORY.createIdentityTokenResponseDOMBuilder();
        b.setContext(request.getContext());
        b.setIdentityToken(createIdentityTokenBuilder(request).build());
        b.setRelatesTo(request.getMessageID());

        return b.build();
    }

    private Document createTestRequestDOM() {
        IdentityTokenRequestDOMBuilder b = IDWSH_FACTORY.createIdentityTokenRequestDOMBuilder();
        b.setAudience(AUDIENCE);
        b.setUserIDCard(createSignedIdCard());
        b.setWSAddressingTo(ADDRESSING_TO);
        return b.build();
    }

    private Document assertToXMLandBack(Document document) throws XMLSecurityException {
        final String c14NStringBefore = SignatureUtil.getC14NString(document.getDocumentElement());
        final String xml = XmlUtil.node2String(document);
        final Document documentAfter = XmlUtil.readXml(new Properties(), xml, VALIDATE_XML);
        final String c14NStringAfter = SignatureUtil.getC14NString(documentAfter.getDocumentElement());
        assertEquals(c14NStringBefore, c14NStringAfter);
        return documentAfter;
    }
}