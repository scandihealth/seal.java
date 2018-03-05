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

import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.model.dombuilders.IdentityTokenRequestDOMBuilder;
import dk.sosi.seal.modelbuilders.IDCardModelBuilder;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.io.StringReader;
import java.net.URL;

import static junit.framework.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class TestIdentityTokenRequestDOMBuilder {

    @Test
    public void testBuild() {
        try {
            final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
            builder.setAudience("http://foobar.dk");
            builder.build();
            fail();
        } catch (ModelException e) {
            assertEquals("idcard is mandatory - but was null.", e.getMessage());
        }

        try {
            final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
            builder.setUserIDCard(createIdCard("someId"));
            builder.build();
            fail();
        } catch (ModelException e) {
            assertEquals("audience is mandatory - but was null.", e.getMessage());
        }

        try {
            final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
            builder.setUserIDCard(createIdCard("someId")).setAudience("");
            builder.build();
            fail();
        } catch (ModelException e) {
            assertEquals("audience is mandatory - but was an empty String.", e.getMessage());
        }

        try {
            final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
            builder.setUserIDCard(createIdCard(null)).setAudience("http://fmk-online.dk");
            builder.build();
            fail();
        } catch (ModelException e) {
            assertEquals("CPR cannot be empty", e.getMessage());
        }

        try {
            final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
            builder.setUserIDCard(createIdCard("someId")).setAudience("http://fmk-online.dk").setWSAddressingTo("");
            builder.build();
            fail();
        } catch (ModelException e) {
            assertEquals("wsAddressingTo is mandatory - but was an empty String.", e.getMessage());
        }

    }

    @Test
    public void testDGWSStyle() {

        final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
        final UserIDCard idCard = createIdCard("someId");
        builder.setUserIDCard(idCard).setAudience("http://fmk-online.dk").requireIDCardInSOAPHeader();
        Document document = builder.build();

        final Element messageID = assertSerializedHeader(document);

        final Element wsseSecurity = (Element) messageID.getNextSibling();
        assertEquals("wsse:Security", wsseSecurity.getTagName());
        assertEquals("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", wsseSecurity.getNamespaceURI());

        final Element idCardElement = (Element) wsseSecurity.getFirstChild();
        final Document idCardDoc = XmlUtil.createEmptyDocument();
        final Node copiedIdCardNode = idCardDoc.importNode(idCardElement, true);
        idCardDoc.appendChild(copiedIdCardNode);
        assertEquals(idCard, new IDCardModelBuilder().buildModel(idCardDoc));

        assertNull(wsseSecurity.getNextSibling());

        final Element actAs = assertSerializedBody((Element) document.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Body").item(0));
        final Element securityTokenReference = (Element) actAs.getFirstChild();
        assertEquals("wsse:SecurityTokenReference", securityTokenReference.getTagName());
        assertEquals("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", securityTokenReference.getNamespaceURI());

        final Element reference = (Element) securityTokenReference.getFirstChild();
        assertEquals("wsse:Reference", reference.getTagName());
        assertEquals("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", reference.getNamespaceURI());

        final String uri = reference.getAttribute("URI");
        assertEquals("#IDCard", uri);
        assertEquals(idCardElement, XmlUtil.getElementByIdExtended(document, uri.substring(1)));
    }

    @Test
    public void testOIOStyle() {
        final IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
        final UserIDCard idCard = createIdCard("someId");
        builder.setUserIDCard(idCard).setAudience("http://fmk-online.dk");
        Document document = builder.build();

        final Element messageID = assertSerializedHeader(document);
        assertNull(messageID.getNextSibling());

        final Element actAs = assertSerializedBody((Element) document.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Body").item(0));
        final Element idCardElement = (Element) actAs.getFirstChild();
        assertEquals("saml:Assertion", idCardElement.getTagName());
        assertEquals("urn:oasis:names:tc:SAML:2.0:assertion", idCardElement.getNamespaceURI());
        assertEquals(idCard, new IDCardModelBuilder().buildModel(document));

        //System.out.println(XmlUtil.node2String(document, true, true));
    }

    @Test
    public void testWSAddressingTo() {
        final String stsEndpoint = "http://pan.certifikat.dk/sts/services/SecurityTokenService";

        IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
        builder.setUserIDCard(createIdCard("someId")).setAudience("http://fmk-online.dk").setWSAddressingTo(stsEndpoint);
        Document document = builder.build();

        Element header = (Element) document.getDocumentElement().getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
        assertEquals(1, header.getElementsByTagNameNS("http://www.w3.org/2005/08/addressing", "To").getLength());
        assertEquals(stsEndpoint, header.getElementsByTagNameNS("http://www.w3.org/2005/08/addressing", "To").item(0).getTextContent());

        builder = new IdentityTokenRequestDOMBuilder();
        builder.setUserIDCard(createIdCard("someId")).setAudience("http://fmk-online.dk").requireIDCardInSOAPHeader().setWSAddressingTo(stsEndpoint);
        document = builder.build();

        header = (Element) document.getDocumentElement().getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
        assertEquals(1, header.getElementsByTagNameNS("http://www.w3.org/2005/08/addressing", "To").getLength());
        assertEquals(stsEndpoint, header.getElementsByTagNameNS("http://www.w3.org/2005/08/addressing", "To").item(0).getTextContent());
    }

    @Test
    public void testAgainstSchema() throws SAXException, IOException {
        schemaValidate(false);
        schemaValidate(true);
    }

    private void schemaValidate(boolean dgwsStyle) throws SAXException, IOException {
        final String stsEndpoint = "http://pan.certifikat.dk/sts/services/SecurityTokenService";

        IdentityTokenRequestDOMBuilder builder = new IdentityTokenRequestDOMBuilder();
        builder.setUserIDCard(createIdCard("someId")).setAudience("http://fmk-online.dk").setWSAddressingTo(stsEndpoint);
        if (dgwsStyle) {
            builder.requireIDCardInSOAPHeader();
        }
        Document document = builder.build();

        final SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        final URL resource = getClass().getResource("/idwsh/idtreq/soap.xsd");
        final Schema schema = factory.newSchema(resource);
        final Validator validator = schema.newValidator();

        // Serialize to String in order to cope with namespace handling for attributes
        final String xmlString = XmlUtil.node2String(document, false, true);
        final StreamSource source = new StreamSource(new StringReader(xmlString));

        validator.validate(source);
    }

    private Element assertSerializedHeader(Document document) {
        assertNotNull(document);
        final Element envelope = document.getDocumentElement();
        assertEquals("soapenv:Envelope", envelope.getTagName());
        assertEquals("http://schemas.xmlsoap.org/soap/envelope/", envelope.getNamespaceURI());
        final Element header = (Element) envelope.getFirstChild();
        assertEquals("soapenv:Header", header.getTagName());
        assertEquals("http://schemas.xmlsoap.org/soap/envelope/", header.getNamespaceURI());
        final Element body = (Element) header.getNextSibling();
        assertEquals("soapenv:Body", body.getTagName());
        assertEquals("http://schemas.xmlsoap.org/soap/envelope/", body.getNamespaceURI());

        final Element action = (Element) header.getFirstChild();
        assertEquals("wsa:Action", action.getTagName());
        assertEquals("http://www.w3.org/2005/08/addressing", action.getNamespaceURI());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", action.getTextContent());

        final Element messageID = (Element) action.getNextSibling();
        assertEquals("wsa:MessageID", messageID.getTagName());
        assertEquals("http://www.w3.org/2005/08/addressing", messageID.getNamespaceURI());
        assertNotNull(messageID.getTextContent());
        assertTrue(messageID.getTextContent().startsWith("urn:uuid:"));
        assertEquals(45, messageID.getTextContent().length());
        return messageID;
    }

    private Element assertSerializedBody(Element body) {
        final Element requestSecurityToken = (Element) body.getFirstChild();
        assertEquals("wst:RequestSecurityToken", requestSecurityToken.getTagName());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512", requestSecurityToken.getNamespaceURI());
        final String context = requestSecurityToken.getAttribute("Context");
        assertNotNull(context);
        assertTrue(context.startsWith("urn:uuid:"));
        assertEquals(45, context.length());

        final Element tokenType = (Element) requestSecurityToken.getFirstChild();
        assertEquals("wst:TokenType", tokenType.getTagName());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512", tokenType.getNamespaceURI());
        assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", tokenType.getTextContent());

        final Element requestType = (Element) tokenType.getNextSibling();
        assertEquals("wst:RequestType", requestType.getTagName());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512", requestType.getNamespaceURI());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue", requestType.getTextContent());

        final Element actAs = (Element) requestType.getNextSibling();
        assertEquals("wst14:ActAs", actAs.getTagName());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200802", actAs.getNamespaceURI());

        final Element appliesTo = (Element) actAs.getNextSibling();
        assertEquals("wsp:AppliesTo", appliesTo.getTagName());
        assertEquals("http://schemas.xmlsoap.org/ws/2004/09/policy", appliesTo.getNamespaceURI());

        final Element endpointReference = (Element) appliesTo.getFirstChild();
        assertEquals("wsa:EndpointReference", endpointReference.getTagName());
        assertEquals("http://www.w3.org/2005/08/addressing", endpointReference.getNamespaceURI());
        assertEquals("http://fmk-online.dk", endpointReference.getTextContent());

        final Element address = (Element) endpointReference.getFirstChild();
        assertEquals("wsa:Address", address.getTagName());
        assertEquals("http://www.w3.org/2005/08/addressing", address.getNamespaceURI());
        assertEquals("http://fmk-online.dk", address.getTextContent());
        return actAs;
    }
    
    private UserIDCard createIdCard(String alternativeIdentifier) {
        return CredentialVaultTestUtil.createSOSIFactory().createNewUserIDCard(
                "testITSystem",
                new UserInfo(null, "Jan", "Riis", "jan<at>lakeside.dk", "hacker", "doctor", "2101"),
                new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
                AuthenticationLevel.NO_AUTHENTICATION,
                null,
                null,
                null,
                alternativeIdentifier);
    }
}