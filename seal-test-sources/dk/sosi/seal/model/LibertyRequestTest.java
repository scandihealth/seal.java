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

import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Date;
import java.util.List;

import static org.junit.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LibertyRequestTest extends AbstractModelTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private Document document;
    private IdentityToken identityToken;

    @Before
    public void setUp() {
        document = XmlUtil.createEmptyDocument();
        Element envelope = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
        document.appendChild(envelope);
        Element header = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_PREFIXED);
        envelope.appendChild(header);
        Element body = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_PREFIXED);
        envelope.appendChild(body);
        identityToken = createBuilder().build();
    }

    @Test
    public void testRequestOK() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhanceAndSign(enhancer);

        final LibertyRequest request = new LibertyRequest(getMockFederation(), document);
        assertNotNull(request);
        assertNotNull(request.getIdentityToken());
    }

    @Test
    public void testTamperedIdentityTokenSignature() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("Signature on IdentityToken is invalid");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhanceAndSign(enhancer);

        final Node issuer = document.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ISSUER).item(0);
        issuer.setTextContent("foo");

        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testMissingIdentityToken() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Could not find SAML assertion element");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhanceAndSign(enhancer);

        final Node assertion = document.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
        assertion.getParentNode().removeChild(assertion);

        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testMissingSecurityHeader() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Could not find SAML assertion element");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhanceAndSign(enhancer);

        final Node security = document.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY).item(0);
        security.getParentNode().removeChild(security);

        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testTamperedLibertySignature() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Liberty signature could not be validated");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhanceAndSign(enhancer);

        final Node body = document.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_UNPREFIXED).item(0);
        body.setTextContent("foo");

        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnMessageID() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element http://www.w3.org/2005/08/addressing#MessageID");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "messageID");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnAction() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element http://www.w3.org/2005/08/addressing#Action");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "action");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnWsaTo() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element http://www.w3.org/2005/08/addressing#To");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "to");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhancer.setWSAddressingTo("http://foo.dk");
        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnFrameworkHeader() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element urn:liberty:sb#Framework");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "sbf");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhancer.setWSAddressingTo("http://foo.dk");
        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnTimestamp() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd#Timestamp");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "ts");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnReferenceToIdentityToken() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#SecurityTokenReference");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "str");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testLibertySignatureMissingSignatureOnBody() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Missing Liberty signature on element http://schemas.xmlsoap.org/soap/envelope/#Body");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                remove(references, "body");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testIdentityTokenExpiredValidLibertyTimestamp() {
        identityToken = createExpiredIdentityToken();

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                Node createdTimestampNode = document.getElementsByTagNameNS(NameSpaces.WSU_SCHEMA, WSUTags.CREATED).item(0);
                createdTimestampNode.setTextContent(XmlUtil.toXMLTimeStamp(d(-8), true));
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        final LibertyRequest request = new LibertyRequest(getMockFederation(), document);

        assertNotNull(request);
        assertNotNull(request.getIdentityToken());
        assertTrue(request.getIdentityToken().getNotOnOrAfter().before(new Date()));
        assertTrue(request.getCreatedTimestamp().before(request.getIdentityToken().getNotOnOrAfter()));
    }

    @Test
    public void testIdentityTokenExpiredInvalidLibertyTimestamp() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Liberty timestamp (wsu:Created) is not within the Identity Tokens validity period");

        identityToken = createExpiredIdentityToken();

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhanceAndSign(enhancer);
        new LibertyRequest(getMockFederation(), document);
    }

    @Test
    public void testCreatedTimestamp() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Could not parse wsu:Created element" +
                                                "");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document) {
            @Override
            protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
                Node createdTimestampNode = document.getElementsByTagNameNS(NameSpaces.WSU_SCHEMA, WSUTags.CREATED).item(0);
                createdTimestampNode.setTextContent("FOO");
                return super.getSignatureConfiguration(securityWsuId, references);
            }
        };

        enhanceAndSign(enhancer);
        LibertyRequest request = new LibertyRequest(getMockFederation(), document);
        request.getCreatedTimestamp();
    }

    @Test
    public void testMessageID() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingMessageID("12345");
        enhanceAndSign(enhancer);

        final LibertyRequest request = new LibertyRequest(getMockFederation(), document);
        assertEquals("12345", request.getMessageID());
    }

    private void remove(List<SignatureConfiguration.Reference> references, String identifier) {
        for (SignatureConfiguration.Reference reference : references) {
            if (reference.getURI().equals(identifier)) {
                references.remove(reference);
                break;
            }
        }
    }

    private void enhanceAndSign(LibertyRequestDOMEnhancer enhancer) {
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();
    }

    private IdentityToken createExpiredIdentityToken() {
        UserIDCard uidc = createUserIDCard();

        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setNotBefore(d(-10));
        itb.setNotOnOrAfter(d(-5));
        itb.setUserIdCard(uidc);
        itb.setIssuer("http://pan.certifikat.dk/sts/services/SecurityTokenService");
        return itb.build();
    }

}
