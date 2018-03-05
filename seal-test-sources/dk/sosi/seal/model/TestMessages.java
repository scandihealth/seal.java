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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/model/TestMessages.java $
 * $Id: TestMessages.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.modelbuilders.IDCardModelBuilder;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.SOSIFederation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import dk.sosi.seal.xml.XmlUtilException;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXParseException;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * @author ${user}
 * @author $$LastChangedBy: ChristianGasser $$
 * @version $$Revision: 33209 $$
 * @since 1.5
 */
public class TestMessages extends TestCase {

	public void testResquestNonSOSIHeaders() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = factory.createNewRequest(false, "flowID");
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		request.setIDCard(factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION,
				null, null, factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
		Document doc = XmlUtil.createEmptyDocument();
		String namespace = "http://foo/1.1";
		Element header = doc.createElementNS(namespace, "foo:whatever");
		header.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:foo", namespace);
		header.appendChild(doc.createTextNode("text"));
		request.addNonSOSIHeader(header);
		String xml = XmlUtil.node2String(request.serialize2DOMDocument());
		Request deserializedRequest = factory.deserializeRequest(xml);
		assertEquals(1, deserializedRequest.getNonSOSIHeaders().size());
		Element deserializedHeader = deserializedRequest.getNonSOSIHeaders().get(0);
		assertEquals(header.getLocalName(), deserializedHeader.getLocalName());
		assertEquals(header.getNamespaceURI(), deserializedHeader.getNamespaceURI());
		String nodeValue = header.getFirstChild().getNodeValue();
		assertEquals(nodeValue, deserializedHeader.getFirstChild().getNodeValue());
	}

	public void testReplyNonSOSIHeaders() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
		Document doc = XmlUtil.createEmptyDocument();
		String namespace = "http://foo/1.1";
		Element header = doc.createElementNS(namespace, "foo:whatever");
		header.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:foo", namespace);
		header.appendChild(doc.createTextNode("text"));
		reply.addNonSOSIHeader(header);
		String xml = XmlUtil.node2String(reply.serialize2DOMDocument());
		Reply deserializedReply = factory.deserializeReply(xml);
		assertEquals(1, deserializedReply.getNonSOSIHeaders().size());
		Element deserializedHeader = deserializedReply.getNonSOSIHeaders().get(0);
		assertEquals(header.getLocalName(), deserializedHeader.getLocalName());
		assertEquals(header.getNamespaceURI(), deserializedHeader.getNamespaceURI());
		assertEquals(header.getFirstChild().getNodeValue(), deserializedHeader.getFirstChild().getNodeValue());
	}

    public void testRequestWSAddressing2004Header() {
        assertWSAHeader(NameSpaces.WSA_SCHEMA);
    }

    public void testRequestWSAddressing2005Header() {
        assertWSAHeader(NameSpaces.WSA_1_0_SCHEMA);
    }

    private void assertWSAHeader(String wsaNamespace) {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Request request = factory.createNewRequest(false, "flowID");
        request.setIDCard(createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "someID"));
        Document doc = request.serialize2DOMDocument();
        Node soapHeader = doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED).item(0);
        soapHeader.insertBefore(doc.createElementNS(wsaNamespace, WSATags.ACTION), soapHeader.getFirstChild());
        String requestString = XmlUtil.node2String(doc);
        Request deserializedRequest = factory.deserializeRequest(requestString);
        assertNotNull(deserializedRequest);
        Element nonSOSIHeader = deserializedRequest.getNonSOSIHeaders().get(0);
        assertEquals(wsaNamespace, nonSOSIHeader.getNamespaceURI());
        assertEquals(WSATags.ACTION, nonSOSIHeader.getTagName());
    }

    public void testSecurityTokenRequestPrefixes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest str = factory.createNewSecurityTokenRequest();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		str.setIDCard(factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION,
				null, null, factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
		String xml = XmlUtil.node2String(str.serialize2DOMDocument());
		xml = changePrefixes(xml);
		SecurityTokenRequest deserializedStr = factory.deserializeSecurityTokenRequest(xml);
		new IDCardValidator().validateIDCard(deserializedStr.getIDCard());
		assertEquals(str, deserializedStr);
	}

	public void testSecurityTokenResponsePrefixes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest request = factory.createNewSecurityTokenRequest();
		SecurityTokenResponse str = factory.createNewSecurityTokenResponse(request);
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		str.setIDCard(factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION,
				null, null, factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
		String xml = XmlUtil.node2String(str.serialize2DOMDocument());
		xml = changePrefixes(xml);
		SecurityTokenResponse deserializedStr = factory.deserializeSecurityTokenResponse(xml);
		new IDCardValidator().validateIDCard(deserializedStr.getIDCard());
		assertEquals(str, deserializedStr);
	}


	public void testSecurityTokenFaultResponsePrefixes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest request = factory.createNewSecurityTokenRequest();
		SecurityTokenResponse str = factory.createNewSecurityTokenErrorResponse(request, "faultCode", "faultString", "faultActor");
		String xml = XmlUtil.node2String(str.serialize2DOMDocument());
		xml = changePrefixes(xml);
		SecurityTokenResponse deserializedStr = factory.deserializeSecurityTokenResponse(xml);
		assertEquals(str, deserializedStr);
	}

    public void testRegularSecurityTokenRequest() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

        Document doc = getNewSecurityTokenRequestDocument(factory);
        SecurityTokenRequest deserializedSecurityTokenRequest = factory.deserializeSecurityTokenRequest(XmlUtil.node2String(doc));
        assertNotNull(deserializedSecurityTokenRequest.getIDCard());
    }

    public void testSecurityTokenRequestMissingSOAPHeader() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Document doc = getNewSecurityTokenRequestDocument(factory);
        Node soapHeader = doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED).item(0);
        soapHeader.getParentNode().removeChild(soapHeader);
        assertSecurityTokenRequestDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    public void testSecurityTokenRequestDuplicateSecurityHeader() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Document doc = getNewSecurityTokenRequestDocument(factory);
        Node securityHeader = doc.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY).item(0);
        securityHeader.getParentNode().appendChild(securityHeader.cloneNode(true));
        try {
            factory.deserializeSecurityTokenRequest(XmlUtil.node2String(doc));
            fail();
        } catch (XmlUtilException e) {
            assertEquals("Expected 1 XML element matching path 'wsse:Security/wsu:Timestamp/wsu:Created' starting from 'soapenv:Header' (prefixes are resolved and may be different in actual XML). Found 2.", e.getMessage());
        }
    }

    public void testSecurityTokenRequestMissingSecurityHeader() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Document doc = getNewSecurityTokenRequestDocument(factory);
        Node securityHeader = doc.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY).item(0);
        securityHeader.getParentNode().removeChild(securityHeader);
        assertSecurityTokenRequestDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    public void testSecurityTokenRequestEmptyBody() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Document doc = getNewSecurityTokenRequestDocument(factory);
        Node requestSecurityTokenElement = doc.getElementsByTagNameNS(NameSpaces.WST_SCHEMA, WSTTags.requestSecurityToken.getTagName()).item(0);
        requestSecurityTokenElement.getParentNode().removeChild(requestSecurityTokenElement);
        assertSecurityTokenRequestDeserializationFailure(factory, doc, ModelBuildException.class, null);
    }

    public void testSecurityTokenRequestEmptyClaims() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Document doc = getNewSecurityTokenRequestDocument(factory);
        Node samlAssertion = doc.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
        samlAssertion.getParentNode().removeChild(samlAssertion);
        assertSecurityTokenRequestDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    private Document getNewSecurityTokenRequestDocument(SOSIFactory factory) {
        SecurityTokenRequest tokenRequest = factory.createNewSecurityTokenRequest();
        UserIDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, null);
        tokenRequest.setIDCard(idCard);
        return tokenRequest.serialize2DOMDocument();
    }

    private void assertSecurityTokenRequestDeserializationFailure(SOSIFactory factory, Document doc, Class exceptionClass, Class causeClass) {
        try {
            factory.deserializeSecurityTokenRequest(XmlUtil.node2String(doc));
            fail("Expected" + exceptionClass);
        } catch (Throwable t) {
            assertTrue("Expected " + exceptionClass + " got " + t.getClass(), exceptionClass.isInstance(t));
            if (causeClass != null) {
                Throwable cause = t.getCause();
                assertTrue("Expected " + causeClass + " got " + cause.getClass(), causeClass.isInstance(cause));
            }
        }
    }

    public void testReplyMissingSoapHeader() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
        Document doc = reply.serialize2DOMDocument();
        Node soapHeader = doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED).item(0);
        soapHeader.getParentNode().removeChild(soapHeader);
        assertReplyDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    public void testReplyMissingSecurityHeader() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
        Document doc = reply.serialize2DOMDocument();
        Node securityHeader = doc.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY).item(0);
        securityHeader.getParentNode().removeChild(securityHeader);
        assertReplyDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    public void testReplyMissingCreatedElement() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
        Document doc = reply.serialize2DOMDocument();
        Node createdElement = doc.getElementsByTagNameNS(NameSpaces.WSU_SCHEMA, WSUTags.CREATED).item(0);
        createdElement.getParentNode().removeChild(createdElement);
        assertReplyDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    public void testReplyMissingMedcomHeader() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
        Document doc = reply.serialize2DOMDocument();
        Node medcomHeader = doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.HEADER).item(0);
        medcomHeader.getParentNode().removeChild(medcomHeader);
        assertReplyDeserializationFailure(factory, doc, XmlUtilException.class, null);
    }

    public void testReplyMissingMedcomLinkingElement() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
        Document doc = reply.serialize2DOMDocument();
        Node medcomHeader = doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.LINKING).item(0);
        medcomHeader.getParentNode().removeChild(medcomHeader);
        assertReplyDeserializationFailure(factory, doc, XmlUtilException.class, SAXParseException.class);
    }

    private void assertReplyDeserializationFailure(SOSIFactory factory, Document doc, Class exceptionClass, Class causeClass) {
        try {
            factory.deserializeReply(XmlUtil.node2String(doc));
            fail("Expected" + exceptionClass);
        } catch (Throwable t) {
            assertTrue("Expected " + exceptionClass + " got " + t.getClass(), exceptionClass.isInstance(t));
            if (causeClass != null) {
                Throwable cause = t.getCause();
                assertTrue("Expected " + causeClass + " got " + cause.getClass(), causeClass.isInstance(cause));
            }
        }
    }

    public void testRequestPrefixes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = factory.createNewRequest(false, "flowID");
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		request.setIDCard(factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION,
				null, null, factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
		String xml = XmlUtil.node2String(request.serialize2DOMDocument());
		xml = changePrefixes(xml);
		Request deserializedRequest = factory.deserializeRequest(xml);
		new IDCardValidator().validateIDCard(deserializedRequest.getIDCard());
		assertEquals(request, deserializedRequest);
	}

	public void testReplyPrefixes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
		String xml = XmlUtil.node2String(reply.serialize2DOMDocument());
		xml = changePrefixes(xml);
		Reply deserializedReply = factory.deserializeReply(xml);
		assertEquals(reply, deserializedReply);
	}

	public void testErrorReplyPrefixes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = factory.createNewRequest(false, "flowID");
		Reply reply = factory.createNewErrorReply(request, "faultCode", "faultString");
		String xml = XmlUtil.node2String(reply.serialize2DOMDocument());
		xml = changePrefixes(xml);
		Reply deserializedReply = factory.deserializeReply(xml);
		assertEquals(reply, deserializedReply);
	}

	private String changePrefixes(String xml) {
		for (Iterator<String> it = NameSpaces.SOSI_NAMESPACES.keySet().iterator(); it.hasNext();) {
			String prefix = it.next();
			String newPrefix = "z" + prefix.substring(1);
			xml = xml.replaceAll(prefix+":", newPrefix + ":");
			xml = xml.replaceAll(":"+prefix, ":"+newPrefix);
			xml = xml.replaceAll("=\""+newPrefix+":", "=\""+prefix+":");
		}
		return xml;
	}

	public void testParseSosiGeneratedFault() {
		// Reply
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		Reply reply = factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, "test", null, FaultCodeValues.INVALID_SIGNATURE, "error message");

		String xml = XmlUtil.node2String(reply.serialize2DOMDocument());
		//TEST
		factory.deserializeReply(xml);

		assertTrue(reply.isFault());
		try {
			reply.getFlowStatus();
			fail("Should not produce flow status for error responses");
		} catch (Exception e) {
			// OK
		}
	}

	public void testSpecialCharacters() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req = factory.createNewSecurityTokenRequest();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		req.setIDCard(factory.createNewSystemIDCard("ØøÅåæÆéΩèçñüÜ!$@", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM,
				null, null, factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));

		Document doc = req.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc,false,true);
		//PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File("c:\\temp\\sosi.xml"))));
		//pw.print(xml);
		//pw.close();
		//System.out.println(xml);
		try {
			req = factory.deserializeSecurityTokenRequest(xml);
			// OK
		} catch (Exception e) {
			fail("Special characters should not break signature!");
		}
	}

	public void testSystemIDCardBinarySerialization() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req = factory.createNewSecurityTokenRequest();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		X509Certificate cert = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		IDCard idcard = factory.createNewSystemIDCard("sosiTest", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, cert, null);
		req.setIDCard(idcard);
		assertNull(idcard.lastDOMOperation);

		// test unsigned idcard serialization
		IDCard serializedUnsignedIDCard = getBinarySerializedIDCard(req);
		assertEquals(idcard, serializedUnsignedIDCard);
		SecurityTokenRequest newReq = factory.createNewSecurityTokenRequest();
		newReq.setIDCard(serializedUnsignedIDCard);
		assertNull(serializedUnsignedIDCard.lastDOMOperation);
		newReq.serialize2DOMDocument();
		assertEquals(IDCard.SIGNED, serializedUnsignedIDCard.lastDOMOperation);

		// Now test a roundtrip with the signed ID-card
		IDCard signedIDCard = newReq.getIDCard();
		IDCard serializedSignedIDCard = getBinarySerializedIDCard(newReq);
		assertEquals(signedIDCard, serializedSignedIDCard);

		SecurityTokenRequest newReqWithSignedIDCard = factory.createNewSecurityTokenRequest();
		newReqWithSignedIDCard.setIDCard(serializedSignedIDCard);
		serializedSignedIDCard.lastDOMOperation = null; // indicator
		newReqWithSignedIDCard.serialize2DOMDocument();
		assertEquals(IDCard.RE_ASSIGNED, serializedSignedIDCard.lastDOMOperation); // Node was reassigned to new DOM Document, but was not re-signed!
	}

	public void testUserIDCardBinarySerialization() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req = factory.createNewSecurityTokenRequest();
		X509Certificate cert = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		IDCard idcard = createNewUserIdCard(factory, AuthenticationLevel.MOCES_TRUSTED_USER, cert, "12345678", null);
		req.setIDCard(idcard);
		assertNull(idcard.lastDOMOperation);

		// test unsigned idcard serialization
		IDCard serializedUnsignedIDCard = getBinarySerializedIDCard(req);
		assertEquals(idcard, serializedUnsignedIDCard);
		SecurityTokenRequest newReq = factory.createNewSecurityTokenRequest();
		newReq.setIDCard(serializedUnsignedIDCard);
		assertNull(serializedUnsignedIDCard.lastDOMOperation);

		// Now test a roundtrip after DOM serialization
		newReq.serialize2DOMDocument();
		assertEquals(IDCard.CREATED, serializedUnsignedIDCard.lastDOMOperation);
		idcard = newReq.getIDCard();
		serializedUnsignedIDCard = getBinarySerializedIDCard(newReq);
		assertEquals(idcard, serializedUnsignedIDCard);

		// Use a serialized/deserialized idcard i a new request
		SecurityTokenRequest newReqWithSignedIDCard = factory.createNewSecurityTokenRequest();
		newReqWithSignedIDCard.setIDCard(serializedUnsignedIDCard);
		serializedUnsignedIDCard.lastDOMOperation = null; // indicator
		newReqWithSignedIDCard.serialize2DOMDocument();
		assertEquals(IDCard.RE_ASSIGNED, serializedUnsignedIDCard.lastDOMOperation); // Node was reassigned to new DOM Document, but was not re-signed!
	}

	public void testUserIDCardXMLSerialization() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req = factory.createNewSecurityTokenRequest();
		X509Certificate cert = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		IDCard idcard = createNewUserIdCard(factory, AuthenticationLevel.MOCES_TRUSTED_USER, cert, "12345678", null);
		req.setIDCard(idcard);
		Document doc = req.serialize2DOMDocument();
		Element idcardElement = (Element)doc.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
		String c14n_one = SignatureUtil.getC14NString(idcardElement);

		// Serialize to XML and deserialize from XML back to DOM
		String idcardAsXML = XmlUtil.node2String(req.getIDCard().serialize2DOMDocument(factory, XmlUtil.createEmptyDocument()));
		Document idcardDoc = XmlUtil.readXml(factory.getProperties(),idcardAsXML,true);
		idcard = new IDCardModelBuilder().buildModel( idcardDoc);
		assertFalse(idcard.needsSignature);
		String c14n_two = SignatureUtil.getC14NString( idcardDoc.getDocumentElement());

		// Check that the  xml representation (plain and c14n) are equal before and after
		assertEquals(XmlUtil.node2String( idcardDoc.getDocumentElement()), XmlUtil.node2String( idcardElement));
		assertEquals(c14n_one, c14n_two);
		// Check that the DOM is equal before and after
		assertNull(XmlUtil.deepDiff(idcardDoc.getDocumentElement(),idcardElement));

		// Create a new request and validate signature
		Request providerRequest = factory.createNewRequest(false,"test");
		providerRequest.setIDCard(idcard);
		doc = providerRequest.serialize2DOMDocument();
	}

	public void testSystemIDCardXMLSerialization() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req = factory.createNewSecurityTokenRequest();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		X509Certificate cert = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		IDCard idcard = factory.createNewSystemIDCard("sosiTest", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, cert, null);
		req.setIDCard(idcard);
		Document doc = req.serialize2DOMDocument();

		// Verify signature
		checkSignature(factory, doc);
		Element idcardElement = (Element)doc.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
		String c14n_one = SignatureUtil.getC14NString(idcardElement);

		// Serialize to XML and deserialize from XML back to DOM
		String idcardAsXML = XmlUtil.node2String(req.getIDCard().serialize2DOMDocument(factory, XmlUtil.createEmptyDocument()));
		Document idcardDoc = XmlUtil.readXml(factory.getProperties(),idcardAsXML,true);
		idcard = new IDCardModelBuilder().buildModel( idcardDoc);
		assertFalse(idcard.needsSignature);
		String c14n_two = SignatureUtil.getC14NString( idcardDoc.getDocumentElement());

		// Check that the  xml representation (plain and c14n) are equal before and after
		assertEquals(XmlUtil.node2String( idcardDoc.getDocumentElement()), XmlUtil.node2String( idcardElement));
		assertEquals(c14n_one, c14n_two);
		// Check that the DOM is equal before and after
		assertNull(XmlUtil.deepDiff(idcardDoc.getDocumentElement(),idcardElement));

		// Create a new request and validate signature
		Request providerRequest = factory.createNewRequest(false,"test");
		providerRequest.setIDCard(idcard);
		doc = providerRequest.serialize2DOMDocument();
		checkSignature(factory, doc);
	}

	public void testRequestAlternativeIdentifier() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
		Request request = factory.createNewRequest(false, "flowID");
		request.setIDCard(idCard);
		String xml = XmlUtil.node2String(request.serialize2DOMDocument(), true, true);
		Request deserializedRequest = factory.deserializeRequest(xml);
		assertEquals(request, deserializedRequest);
		assertEquals(idCard, deserializedRequest.getIDCard());
	}

	public void testNoIDAttributeForEnvelope() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
		Request request = factory.createNewRequest(false, "flowID");
		request.setIDCard(idCard);
		Document doc = request.serialize2DOMDocument();
		Element envelope = doc.getDocumentElement();
		envelope.removeAttribute("id");
		String xml = XmlUtil.node2String(doc, true, true);
		Request deserializedRequest = factory.deserializeRequest(xml);
		assertEquals(request, deserializedRequest);
	}

	public void testCDATASectionInMessage() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Reply reply = factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, "inResponseToID", "flowID", "123", "Wrong authenticationlevel");
		String xml = XmlUtil.node2String(reply.serialize2DOMDocument(), true, true);
		xml = xml.replaceFirst("<medcom:FaultCode>123</medcom:FaultCode>", "<medcom:FaultCode><![CDATA[123]]></medcom:FaultCode>");
		xml = xml.replaceFirst("<faultstring>Wrong authenticationlevel</faultstring>", "<faultstring><![CDATA[Wrong authenticationlevel]]></faultstring>");
		Reply deserializedReply = factory.deserializeReply(xml);
		assertEquals("123", deserializedReply.getFaultCode());
		assertEquals("Wrong authenticationlevel", deserializedReply.getFaultString());
	}

    public void testErrorReplyWithExtraFaultDetails() {
        SOSIFactory factory = new SOSIFactory(new EmptyCredentialVault(), System.getProperties());

        Request request = factory.createNewRequest(false, "flowID");
        Reply replyWithoutExtraDetails = factory.createNewErrorReply(request, "server", "Some terrible error has happened!", null);
        assertTrue(replyWithoutExtraDetails.isFault());
        assertEquals(0, replyWithoutExtraDetails.getExtraFaultDetails().size());

        String replyWithoutExtraDetailsAsString = XmlUtil.node2String(replyWithoutExtraDetails.serialize2DOMDocument());
        Reply deserializedWithoutExtraDetailsReply = factory.deserializeReply(replyWithoutExtraDetailsAsString);
        assertTrue(deserializedWithoutExtraDetailsReply.isFault());
        assertEquals(0, deserializedWithoutExtraDetailsReply.getExtraFaultDetails().size());

        Document doc = XmlUtil.createEmptyDocument();
        String namespaceOne = "http://foo/1.1";
        Element extraDetailOne = doc.createElementNS(namespaceOne, "foo:whatever");
        extraDetailOne.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:foo", namespaceOne);
        extraDetailOne.appendChild(doc.createTextNode("some text"));
        String namespaceTwo = "http://bar/2.2";
        Element extraDetailTwo = doc.createElementNS(namespaceTwo, "bar:WHATEVER");
        extraDetailTwo.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:bar", namespaceTwo);
        Element faultCode = doc.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FAULT_CODE_PREFIXED);
        faultCode.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:" + NameSpaces.NS_MEDCOM, NameSpaces.MEDCOM_SCHEMA);
        extraDetailTwo.appendChild(faultCode);
        List<Element> extraDetails = new LinkedList<Element>();
        extraDetails.add(extraDetailOne);
        extraDetails.add(extraDetailTwo);
        Reply reply = factory.createNewErrorReply(request, "server", "This is bad! Yet another terrible error has happened!", extraDetails);
        assertTrue(reply.isFault());
        assertEquals(2, reply.getExtraFaultDetails().size());
        assertEquals(extraDetailOne, reply.getExtraFaultDetails().get(0));
        assertEquals(extraDetailTwo, reply.getExtraFaultDetails().get(1));

        String replyAsString = XmlUtil.node2String(reply.serialize2DOMDocument());
        Reply deserializedReply = factory.deserializeReply(replyAsString);
        assertTrue(deserializedReply.isFault());
        assertEquals(2, deserializedReply.getExtraFaultDetails().size());

        Element deserializedDetailOne = deserializedReply.getExtraFaultDetails().get(0);
        assertEquals(namespaceOne, deserializedDetailOne.getNamespaceURI());
        assertEquals("whatever", deserializedDetailOne.getLocalName());
        assertEquals("some text", deserializedDetailOne.getTextContent());

        Element deserializedDetailTwo = deserializedReply.getExtraFaultDetails().get(1);
        assertEquals(namespaceTwo, deserializedDetailTwo.getNamespaceURI());
        assertEquals("WHATEVER", deserializedDetailTwo.getLocalName());
        assertEquals(NameSpaces.MEDCOM_SCHEMA, deserializedDetailTwo.getFirstChild().getNamespaceURI());
        assertEquals(MedComTags.FAULT_CODE, deserializedDetailTwo.getFirstChild().getLocalName());

        Reply regularReply = factory.createNewReply(request, FlowStatusValues.FLOW_FINALIZED_SUCCESFULLY);
        assertFalse(regularReply.isFault());
        try {
            regularReply.getExtraFaultDetails();
            fail("Calling getExtraFaultDetails() on a regular reply should fail");
        } catch (ModelException e) {
            // Expected
        }
    }

    public void testSecurityTokenResponseTrustValidation() {
        Properties properties = System.getProperties();

        GenericCredentialVault vault = CredentialVaultTestUtil.getOCES2CredentialVault();
        SOSIFactory factory = new SOSIFactory(vault, properties);

        // Create SecurityTokenResponse with signed idcard
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis");
        IDCard idCard = factory.createNewSystemIDCard("IT-System", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, null, null);
        SecurityTokenResponse securityTokenResponse = factory.createNewSecurityTokenResponse(DGWSConstants.VERSION_1_0_1, "unknown");
        securityTokenResponse.setIDCard(idCard);
        String responseString = XmlUtil.node2String(securityTokenResponse.serialize2DOMDocument());

        SecurityTokenResponse deserializedResponse = factory.deserializeSecurityTokenResponse(responseString);
        deserializedResponse.getIDCard().validateSignatureAndTrust(vault);

        deserializedResponse = new SOSIFactory(new EmptyCredentialVault(), properties).deserializeSecurityTokenResponse(responseString);
        deserializedResponse.getIDCard().validateSignatureAndTrust(vault);

        deserializedResponse = new SOSIFactory(new SOSITestFederation(properties), new EmptyCredentialVault(), properties).deserializeSecurityTokenResponse(responseString);
        deserializedResponse.getIDCard().validateSignatureAndTrust(vault);

        deserializedResponse = new SOSIFactory(new SOSIFederation(properties), new EmptyCredentialVault(), properties).deserializeSecurityTokenResponse(responseString);
        deserializedResponse.getIDCard().validateSignatureAndTrust(vault);

        properties.put(SOSIFactory.PROPERTYNAME_SOSI_CHECK_TRUST_FOR_SECURITY_TOKEN_RESPONSE, "true");

        deserializedResponse = factory.deserializeSecurityTokenResponse(responseString);
        deserializedResponse.getIDCard().validateSignatureAndTrust(vault);

        try {
            new SOSIFactory(new EmptyCredentialVault(), properties).deserializeSecurityTokenResponse(responseString);
            fail();
        } catch (CredentialVaultException e) {
            assertEquals("EmptyVault does not have TrustedCertificate", e.getMessage());
        }

        try {
            new SOSIFactory(new SOSITestFederation(properties), new EmptyCredentialVault(), properties).deserializeSecurityTokenResponse(responseString);
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

        try {
            new SOSIFactory(new SOSIFederation(properties), new EmptyCredentialVault(), properties).deserializeSecurityTokenResponse(responseString);
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

    }

    public void testRequestWithEmptyFlowIdElement() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
        Request request = factory.createNewRequest(false, "flowID");
        request.setIDCard(idCard);
        Document doc = request.serialize2DOMDocument();
        Element envelope = doc.getDocumentElement();
        Node flowIdNode = envelope.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FLOW_ID).item(0);
        flowIdNode.removeChild(flowIdNode.getFirstChild());
        String xml = XmlUtil.node2String(envelope);
        try {
            factory.deserializeRequest(xml);
            fail();
        } catch (ModelBuildException e) {
            assertEquals("DGWS violation: FlowID element must not be empty!", e.getMessage());
        }
    }

    public void testRequestWithEmptyMessageIdElement() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
        Request request = factory.createNewRequest(false, "flowID");
        request.setIDCard(idCard);
        Document doc = request.serialize2DOMDocument();
        Element envelope = doc.getDocumentElement();
        Node messageIdNode = envelope.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.MESSAGE_ID).item(0);
        messageIdNode.removeChild(messageIdNode.getFirstChild());
        String xml = XmlUtil.node2String(envelope);
        try {
            factory.deserializeRequest(xml);
            fail();
        } catch (ModelBuildException e) {
            assertEquals("DGWS violation: MessageID element must not be empty!", e.getMessage());
        }
    }

    public void testIDCardWithEmptySamlAttributeValue() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
        Element idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
        Node attributeValue = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE_VALUE).item(0);
        attributeValue.removeChild(attributeValue.getFirstChild());
        String xml = XmlUtil.node2String(idCardElement);
        try {
            factory.deserializeIDCard(xml);
            fail();
        } catch (XmlUtilException e) {
            assertEquals("The supplied element <saml:AttributeValue xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/> doesn't have child nodes", e.getMessage());
        }
    }

    public void testIDCardWithMissingSamlAttributeValueBuiltDirectlyWithIDCardModelBuilder() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
        Element idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
        Node attributeValue = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE_VALUE).item(0);
        attributeValue.getParentNode().removeChild(attributeValue);
        try {
            new IDCardModelBuilder().buildModel(idCardElement);
            fail();
        } catch (ModelBuildException e) {
            assertEquals("Missing 'saml:AttributeValue' element for 'saml:Attribute' element 'sosi:IDCardID'" , e.getMessage());
        }
    }

    public void testIDCardWithMissingNameFormatAttributeInCareProvider() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null, "alternativeID");
        Element idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
        NodeList samlAttributeNodes = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE);
        for (int samlAttributeCount = 0; samlAttributeCount < samlAttributeNodes.getLength(); samlAttributeCount++) {
            Element samlAttribute = (Element) samlAttributeNodes.item(samlAttributeCount);
            String attributeName = samlAttribute.getAttributes().getNamedItem(SAMLAttributes.NAME).getNodeValue();
            if (MedcomAttributes.CARE_PROVIDER_ID.equals(attributeName)) {
                samlAttribute.removeAttribute(SAMLAttributes.NAME_FORMAT);
                break;
            }
        }
        String xml = XmlUtil.node2String(idCardElement);
        try {
            factory.deserializeIDCard(xml);
            fail();
        } catch (ModelBuildException e) {
            assertEquals("DGWS violation: 'medcom:CareProviderID' SAML attribute must contain a 'NameFormat' attribute!", e.getMessage());
        }
    }

    // ===========================
	// Private parts
	// ===========================

	private void checkSignature(SOSIFactory factory, Document doc) {
		Node signature = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE).item(0);
		assertNotNull(signature);
		assertTrue(SignatureUtil.validate(signature, factory.getFederation(), factory.getCredentialVault(),true));
	}

	private IDCard getBinarySerializedIDCard(SecurityTokenRequest req) throws IOException, ClassNotFoundException {
		ByteArrayOutputStream bas = new ByteArrayOutputStream();
		ObjectOutputStream ous = new ObjectOutputStream(new BufferedOutputStream(bas));
		ous.writeObject(req.getIDCard());
		ous.flush();
		byte[] array = bas.toByteArray();
		ous.close();

//System.out.println("Length: "+array.length);

		ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(array));
		IDCard idcard = (IDCard)ois.readObject();
		assertEquals(req.getIDCard(),idcard);
		return idcard;
	}

	private UserIDCard createNewUserIdCard(SOSIFactory factory, AuthenticationLevel authLevel, X509Certificate certificate, String cpr, String alternativeIdentifier) {
		return factory.createNewUserIDCard(
				"testITSystem",
					new UserInfo(cpr, "Jan", "Riis", "jan<at>lakeside.dk", "hacker", "doctor", "2101"),
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
					authLevel,
					null,
					null,
					certificate,
					alternativeIdentifier);
	}
}
