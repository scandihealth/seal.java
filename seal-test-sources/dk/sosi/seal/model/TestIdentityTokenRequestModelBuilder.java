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

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.model.constants.WSATags;
import dk.sosi.seal.model.dombuilders.IdentityTokenRequestDOMBuilder;
import dk.sosi.seal.modelbuilders.IdentityTokenRequestModelBuilder;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.security.cert.X509Certificate;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class TestIdentityTokenRequestModelBuilder extends TestCase {

    public void testBuildDgwsStyle() {
        assertBuild(true);
    }

    public void testBuildOioStyle() {
        assertBuild(false);
    }

    public void testTamperSignature() {
        final String stsEndpoint = "http://pan.certifikat.dk/sts/services/SecurityTokenService";

        IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
        final UserIDCard idCard = createSignedIdCard();
        builder.setUserIDCard(idCard).setAudience("http://fmk-online.dk").setWSAddressingTo(stsEndpoint);

        String xmlString = XmlUtil.node2String(builder.build(), false, true);

        xmlString = xmlString.replace("Jan", "Peter");

        final Document document = XmlUtil.readXml(System.getProperties(), xmlString, false);

        try {
            new IdentityTokenRequestModelBuilder(getMockFederation()).buildModel(document);
            fail();
        } catch (ModelBuildException e) {
           assertEquals("Signature on IdCard could not be validated", e.getMessage());
        }
    }

    public void assertBuild(boolean dgwsStyle) {
        final String stsEndpoint = "http://pan.certifikat.dk/sts/services/SecurityTokenService";

        IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
        final UserIDCard idCard = createSignedIdCard();
        builder.setUserIDCard(idCard).setAudience("http://fmk-online.dk").setWSAddressingTo(stsEndpoint);
        if (dgwsStyle) {
            builder.requireIDCardInSOAPHeader();
        }

        // Serialize to String in order to cope with namespace handling for attributes
        final String xmlString = XmlUtil.node2String(builder.build(), false, true);
        final Document document = XmlUtil.readXml(System.getProperties(), xmlString, false);

        //System.out.println(XmlUtil.node2String(builder.build(), true, true));

        IdentityTokenRequest identityTokenRequest = new IdentityTokenRequestModelBuilder(getMockFederation()).buildModel(document);

        assertTrue(identityTokenRequest.getMessageID().startsWith("urn:uuid:"));
        assertTrue(identityTokenRequest.getContext().startsWith("urn:uuid:"));
        assertEquals("http://fmk-online.dk", identityTokenRequest.getAudience());
        assertEquals(idCard, identityTokenRequest.getIDCard());

        Node messageID = document.getElementsByTagNameNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID).item(0);
        messageID.getParentNode().removeChild(messageID);
        identityTokenRequest = new IdentityTokenRequestModelBuilder(getMockFederation()).buildModel(document);
        assertNull(identityTokenRequest.getMessageID());
    }

    private UserIDCard createSignedIdCard() {
        final SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        final UserIDCard idCard = factory.createNewUserIDCard(
                "testITSystem",
                new UserInfo("1111111118", "Jan", "Riis", "jan<at>lakeside.dk", "hacker", "doctor", "2101"),
                new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
                AuthenticationLevel.MOCES_TRUSTED_USER,
                null,
                null,
                null,
                null);
        final SecurityTokenRequest tokenRequest = factory.createNewSecurityTokenRequest();
        tokenRequest.setIDCard(idCard);
        idCard.sign(tokenRequest.serialize2DOMDocument(), factory.getSignatureProvider());
        return idCard;
    }

    private Federation getMockFederation() {
        return new SOSITestFederation(System.getProperties()) {
            @Override
            public boolean isValidSTSCertificate(X509Certificate certificate) {
                return CredentialVaultTestUtil.createSOSIFactory().getCredentialVault().getSystemCredentialPair().getCertificate().equals(certificate);
            }
        };

    }


}
