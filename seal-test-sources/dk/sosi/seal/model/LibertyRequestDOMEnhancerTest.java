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
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.Transforms;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import static junit.framework.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LibertyRequestDOMEnhancerTest extends AbstractModelTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private Document document;
    private Element envelope;
    private Element header;
    private Element body;
    private IdentityToken identityToken;

    @Before
    public void setUp() {
        document = XmlUtil.createEmptyDocument();
        envelope = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
        document.appendChild(envelope);
        header = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_PREFIXED);
        envelope.appendChild(header);
        body = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_PREFIXED);
        envelope.appendChild(body);
        identityToken = createBuilder().build();
    }

    @After
    public void tearDown() {
        document = null;
        envelope = null;
        header = null;
        body = null;
        identityToken = null;
    }

    @Test
    public void testNullCredentialVault() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("CredentialVault cannot be null");

        new LibertyRequestDOMEnhancer(null, document);
    }

    @Test
    public void testNullDocument() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Document cannot be null");

        new LibertyRequestDOMEnhancer(new EmptyCredentialVault(), null);
    }

    @Test
    public void testNullWSAddressingMessageID() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingMessageID' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingMessageID(null);
    }

    @Test
    public void testEmptyWSAddressingMessageID() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingMessageID' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingMessageID("");
    }

    @Test
    public void testNullWSAddressingAction() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingAction' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction(null);
    }

    @Test
    public void testEmptyWSAddressingAction() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingAction' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("");
    }

    @Test
    public void testNullWSAddressingTo() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingTo' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingTo(null);
    }

    @Test
    public void testEmptyWSAddressingTo() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingTo' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingTo("");
    }

    @Test
    public void testNullWSAddressingRelatesTo() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingRelatesTo' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingRelatesTo(null);
    }

    @Test
    public void testEmptyWSAddressingRelatesTo() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'wsAddressingRelatesTo' cannot be null or empty");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingRelatesTo("");
    }

    @Test
    public void testNullIdentityToken() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'identityToken' cannot be null");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setIdentityToken(null);
    }

    @Test
    public void testSchemaValidationOK() {
        new LibertyRequestDOMEnhancer(credentialVault, document);
    }

    @Test
    public void testSchemaValidationIdAttributeOnEnvelope() {
        envelope.setAttributeNS(null, IDValues.id, "envelope");
        new LibertyRequestDOMEnhancer(credentialVault, document);
    }

    @Test(expected = ModelBuildException.class)
    public void testSchemaValidationMissingBody() {
        envelope.removeChild(body);

        new LibertyRequestDOMEnhancer(credentialVault, document);
    }

    @Test
    public void testMissingRequiredWSAddressingAction() {
        expectedException.expect(ModelBuildException.class);
        expectedException.expectMessage("Required element 'Action' in namespace 'http://www.w3.org/2005/08/addressing' not present in document. Failed to set it as no value has been provided for it.");

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();
    }

    @Test
    public void testMissingRequiredIdentityToken() {
        expectedException.expect(ModelBuildException.class);

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.enhanceAndSign();
    }

    @Test
    public void testSetIdAttributesAndRequiredHeaders() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();

        assertEquals("body", body.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));

        final Element messageID = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID);
        assertNotNull(messageID);
        assertTrue(messageID.getTextContent().startsWith("urn:uuid:"));
        assertNotNull(UUID.fromString(messageID.getTextContent().substring("urn:uuid:".length())));
        final String messageIDWsuId = messageID.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED);
        assertEquals("messageID", messageIDWsuId);

        final Element action = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION);
        assertNotNull(action);
        assertEquals("http://foo.com#bar", action.getTextContent());
        final String actionWsuId = action.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED);
        assertEquals("action", actionWsuId);

        final Element framework = XmlUtil.getFirstChildElementNS(header, NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK);
        assertNotNull(framework);
        assertEquals("2.0", framework.getAttribute(LibertyAttributes.VERSION));
        assertEquals("urn:liberty:sb:profile:basic", framework.getAttributeNS(NameSpaces.LIBERTY_SBF_PROFILE_SCHEMA, LibertyAttributes.PROFILE));
        final String frameworkWsuId = framework.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED);
        assertEquals("sbf", frameworkWsuId);
    }

    @Test
    public void testSetOptionalHeaders() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.setIdentityToken(identityToken);

        enhancer.setWSAddressingMessageID("1234");
        enhancer.setWSAddressingTo("http://bar.com");
        enhancer.setWSAddressingRelatesTo("_45dfdsfa0232-3");

        enhancer.enhanceAndSign();

        final Element messageID = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID);
        assertEquals("1234", messageID.getTextContent());

        final Element to = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.TO);
        assertEquals("http://bar.com", to.getTextContent());

        final Element relatesTo = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.RELATES_TO);
        assertEquals("_45dfdsfa0232-3", relatesTo.getTextContent());
    }

    @Test
    public void testIdAttributesAndHeadersAlreadyPresent() {
        body.setAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_PREFIXED, "fooBody");

        final Element messageID = document.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID_PREFIXED);
        messageID.setAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_PREFIXED, "fooMessageID");
        messageID.setTextContent("2345");
        header.appendChild(messageID);

        final Element action = document.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION_PREFIXED);
        action.setAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_PREFIXED, "fooAction");
        action.setTextContent("http://foo.com#bar");
        header.appendChild(action);

        final Element to = document.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.TO_PREFIXED);
        to.setAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_PREFIXED, "fooTo");
        to.setTextContent("http://foo.com");
        header.appendChild(to);

        final Element framework = document.createElementNS(NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK_PREFIXED);
        framework.setAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_PREFIXED, "fooSBF");
        header.appendChild(framework);

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();

        assertEquals("fooBody", body.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));
        assertEquals("fooMessageID", messageID.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));
        assertEquals("fooAction", action.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));
        assertEquals("fooTo", to.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));
        assertEquals("fooSBF", framework.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));

        assertEquals("2345", messageID.getTextContent());
        assertEquals("http://foo.com#bar", action.getTextContent());
        assertEquals("http://foo.com", to.getTextContent());
    }

    @Test
    public void testReplaceExistingHeaders() {
        final Element messageID = document.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID_PREFIXED);
        messageID.setTextContent("3456");
        header.appendChild(messageID);

        final Element action = document.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION_PREFIXED);
        action.setTextContent("http://foo.com#bar");
        header.appendChild(action);

        final Element to = document.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.TO_PREFIXED);
        to.setTextContent("http://bar.dk");
        header.appendChild(to);

        final Element framework = document.createElementNS(NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK_PREFIXED);
        framework.setAttributeNS(null, LibertyAttributes.VERSION, "1.0");
        framework.setAttributeNS(NameSpaces.LIBERTY_SBF_PROFILE_SCHEMA, LibertyAttributes.PROFILE_PREFIXED, "foo");
        header.appendChild(framework);

        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingMessageID("1234");
        enhancer.setWSAddressingAction("http://bar.com#Issue");
        enhancer.setWSAddressingTo("http://foo.dk");
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();

        assertEquals("1234", messageID.getTextContent());
        assertEquals("http://bar.com#Issue", action.getTextContent());
        assertEquals("http://foo.dk", to.getTextContent());
        assertEquals("2.0", framework.getAttribute(LibertyAttributes.VERSION));
        assertEquals("urn:liberty:sb:profile:basic", framework.getAttributeNS(NameSpaces.LIBERTY_SBF_PROFILE_SCHEMA, LibertyAttributes.PROFILE));
    }

    @Test
    public void testOldWSAddressingVersion() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("Document contains WS-Addressing headers in 'http://schemas.xmlsoap.org/ws/2004/08/addressing' namespace. " + "Only WS-Addressing 1.0 (namespace 'http://www.w3.org/2005/08/addressing') supported as required by the Liberty Basic SOAP Binding is supported.");

        final Element action = document.createElementNS(NameSpaces.WSA_SCHEMA, WSATags.ACTION_PREFIXED);
        action.setTextContent("http://foo.dk#Revoke");
        header.appendChild(action);

        minimalEnhanceAndSign();
    }

    @Test
    public void testExistingWSSecurityHeader() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("Document already contains a WS-Security header!");

        final Element security = document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY);
        header.appendChild(security);

        minimalEnhanceAndSign();
    }

    @Test
    public void testWSSecurityHeader() throws ParseException {
        minimalEnhanceAndSign();

        final Element securityHeader = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY);
        assertNotNull(securityHeader);
        assertEquals("1", securityHeader.getAttribute("mustUnderstand"));

        final Element timestamp = XmlUtil.getFirstChildElementNS(securityHeader, NameSpaces.WSU_SCHEMA, WSUTags.TIMESTAMP);
        assertNotNull(timestamp);
        assertEquals("ts", timestamp.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));
        final Element created = XmlUtil.getFirstChildElementNS(timestamp, NameSpaces.WSU_SCHEMA, WSUTags.CREATED);
        assertNotNull(created);
        assertNotNull(XmlUtil.fromXMLTimeStamp(created.getTextContent()));

        final Element samlAssertion = XmlUtil.getFirstChildElementNS(securityHeader, NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION);
        assertNotNull(samlAssertion);
        // TODO assertEquals on identityTokens, but we need a method to deserialize an identitytoken ....

        final Element securityTokenReference = XmlUtil.getFirstChildElementNS(securityHeader, NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY_TOKEN_REFERENCE);
        assertNotNull(securityTokenReference);
        assertEquals("str", securityTokenReference.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED));
        assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", securityTokenReference.getAttributeNS(NameSpaces.WSSE_1_1_SCHEMA, WSSE11Attributes.TOKEN_TYPE));

        final Element keyIdentifier = XmlUtil.getFirstChildElementNS(securityTokenReference, NameSpaces.WSSE_SCHEMA, WSSETags.KEY_IDENTIFIER);
        assertNotNull(keyIdentifier);
        assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", keyIdentifier.getAttribute(WSSEAttributes.VALUE_TYPE));
        assertEquals(identityToken.getID(), keyIdentifier.getTextContent());

    }

    @Test
    public void testSignatureOnIdentityToken() {
        final Element libertySignature = minimalEnhanceAndSign();

        final Element assertion = (Element)header.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
        final Element tokenSignature = XmlUtil.getFirstChildElementNS(assertion, NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);

        final Node digestValueNode = libertySignature.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "DigestValue").item(0);
        final String digest = digestValueNode.getTextContent();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
        assertTrue(SignatureUtil.validate(tokenSignature, getMockFederation(), null, true));

        digestValueNode.setTextContent("FOO");
        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
        assertTrue(SignatureUtil.validate(tokenSignature, getMockFederation(), null, true));

        digestValueNode.setTextContent(digest);
        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        Node audienceValueNode = header.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, "Audience").item(0);
        String audience = audienceValueNode.getTextContent();

        audienceValueNode.setTextContent("BAR");
        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
        assertFalse(SignatureUtil.validate(tokenSignature, getMockFederation(), null, true));

        audienceValueNode.setTextContent(audience);
        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
        assertTrue(SignatureUtil.validate(tokenSignature, getMockFederation(), null, true));

        header.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY_TOKEN_REFERENCE).item(0).getFirstChild().setTextContent("FOO");
        try {
            SignatureUtil.validate(libertySignature, getMockFederation(), null, true);
        } catch (ModelException e) {
            assertEquals("Unable to validate the xmlSignature", e.getMessage());
        }
        assertTrue(SignatureUtil.validate(tokenSignature, getMockFederation(), null, true));
    }

    @Test
    public void testSignatureOnWSAddressingMessageID() {
        final Element libertySignature = minimalEnhanceAndSign();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        final Element messageID = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID);
        messageID.setTextContent(messageID.getTextContent() + "XXX");

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }

    @Test
    public void testSignatureOnWSAddressingAction() {
        final Element libertySignature = minimalEnhanceAndSign();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        final Element action = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION);
        action.setTextContent(action.getTextContent() + "XXX");

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }

    @Test
    public void testSignatureOnWSAddressingTo() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.setWSAddressingTo("http://foo.com");
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();

        final Element security = (Element)header.getLastChild();
        final Element libertySignature = (Element)security.getLastChild();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        final Element to = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.TO);
        to.setTextContent(to.getTextContent() + "XXX");

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }


    @Test
    public void testSignatureOnWSAddressingRelatesTo() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.setWSAddressingRelatesTo("_12ffrsdafdsfe3234");
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();

        final Element security = (Element)header.getLastChild();
        final Element libertySignature = (Element)security.getLastChild();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        final Element relatesTo = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.RELATES_TO);
        relatesTo.setTextContent(relatesTo.getTextContent() + "XXX");

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }

    @Test
    public void testSignatureOnLibertyFrameworkHeader() {
        final Element libertySignature = minimalEnhanceAndSign();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        final Element framework = XmlUtil.getFirstChildElementNS(header, NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK);
        framework.setTextContent(framework.getTextContent() + "XXX");

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }

    @Test
    public void testSignatureOnTimestamp() throws ParseException {
        final Element libertySignature = minimalEnhanceAndSign();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        final Node wsuCreated = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY).getFirstChild().getFirstChild();
        final Date date = XmlUtil.fromXMLTimeStamp(wsuCreated.getTextContent());
        wsuCreated.setTextContent(XmlUtil.toXMLTimeStamp(new Date(date.getTime() + 1000), true));

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }

    @Test
    public void testSignatureOnBody() {
        final Element libertySignature = minimalEnhanceAndSign();

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));

        body.setAttributeNS(null, "foo", "bar");

        assertFalse(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
    }

    @Test
    public void testSerializeToString() throws XMLSecurityException {
        minimalEnhanceAndSign();
        final String xml = XmlUtil.node2String(document);
        final Document doc = XmlUtil.readXml(System.getProperties(), xml, false);

        final String c14NStringMessageIDBefore = SignatureUtil.getC14NString(XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID));
        final String c14NStringMessageIDAfter = SignatureUtil.getC14NString(XmlUtil.getFirstChildElementNS((Element)doc.getDocumentElement().getFirstChild(), NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID));
        assertEquals(c14NStringMessageIDBefore, c14NStringMessageIDAfter);

        final String c14NStringActionBefore = SignatureUtil.getC14NString(XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION));
        final String c14NStringActionAfter = SignatureUtil.getC14NString(XmlUtil.getFirstChildElementNS((Element)doc.getDocumentElement().getFirstChild(), NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION));
        assertEquals(c14NStringActionBefore, c14NStringActionAfter);

        final String c14NStringLibertyFrameworkBefore = SignatureUtil.getC14NString(XmlUtil.getFirstChildElementNS(header, NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK));
        final String c14NStringLibertyFrameworkAfter = SignatureUtil.getC14NString(XmlUtil.getFirstChildElementNS((Element)doc.getDocumentElement().getFirstChild(), NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK));
        assertEquals(c14NStringLibertyFrameworkBefore, c14NStringLibertyFrameworkAfter);

        final Node libertySignature = doc.getDocumentElement().getFirstChild().getLastChild().getLastChild();

        final Element assertion = (Element)doc.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
        final Element tokenSignature = XmlUtil.getFirstChildElementNS(assertion, NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);

        assertTrue(SignatureUtil.validate(libertySignature, getMockFederation(), null, true));
        assertTrue(SignatureUtil.validate(tokenSignature, getMockFederation(), null, true));

    }

    @Test
    public void testNoEnvelopedTransformation() {
        final Element libertySignature = minimalEnhanceAndSign();
        String libertySignatureXml = XmlUtil.node2String(libertySignature);
        assertTrue("Liberty signature should contain enveloped transforms, as the signature is not enveloped!", libertySignatureXml.indexOf(Transforms.TRANSFORM_ENVELOPED_SIGNATURE) == -1);
    }

    private Element minimalEnhanceAndSign() {
        final LibertyRequestDOMEnhancer enhancer = new LibertyRequestDOMEnhancer(credentialVault, document);
        enhancer.setWSAddressingAction("http://foo.com#bar");
        enhancer.setIdentityToken(identityToken);
        enhancer.enhanceAndSign();

        final Element security = (Element)header.getLastChild();
        return (Element)security.getLastChild();
    }

}
