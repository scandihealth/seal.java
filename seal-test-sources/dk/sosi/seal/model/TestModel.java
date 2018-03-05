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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/model/TestModel.java $
 * $Id: TestModel.java 34042 2017-03-13 13:38:28Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.model.dombuilders.DOMBuilderException;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.modelbuilders.ModelPrefixResolver;
import dk.sosi.seal.modelbuilders.SignatureInvalidModelBuildException;
import dk.sosi.seal.pki.CredentialVaultSignatureProvider;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Test the model package
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class TestModel extends TestCase {

	private Properties properties;
	private static long HOUR_IN_MILLIS = 60*60*1000;

	protected void setUp() throws Exception {
		super.setUp();
		properties = SignatureUtil.setupCryptoProviderForJVM();
	}

	public void testEmbeddedBodyElementRequest() throws Exception {

		// Request
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, null, false);
		Document doc = XmlUtil.createEmptyDocument();
		Element bodyElement = doc.createElement("SomeXML");
		bodyElement.appendChild(doc.createElement("SomeNestedXML"));
		req.setBody(bodyElement);

		req = cloneRequestBySerialization(factory, req);
		assertNull(XmlUtil.deepDiff(bodyElement, req.getBody()));
	}

	public void testEmbeddedBodyElementReply() throws Exception {

		// Reply
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
		try {
			reply.getFaultCode();
			fail("Should not produce faultcode for non-error responses");
		} catch (Exception e) {
			// OK
		}
		try {
			reply.getFaultString();
			fail("Should not produce faultstring for non-error responses");
		} catch (Exception e) {
			// OK
		}
		Document doc = XmlUtil.createEmptyDocument();
		Element bodyElement = doc.createElement("SomeXML");
		bodyElement.appendChild(doc.createElement("SomeNestedXML"));
		reply.setBody(bodyElement);
		IDCard idcard = factory.createNewSystemIDCard(
				"test",
				new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
				AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null,
				factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
		reply.setIDCard(idcard);

		reply = cloneReplyBySerialization(factory, reply);
		assertNull(XmlUtil.deepDiff(bodyElement, reply.getBody()));
	}

	public void testEmbeddedBodyFaultElementReply() throws Exception {

		String ERROR_MESSAGE = "The supplied signature is invalid";
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		// Reply
		Reply reply = factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, "test", null, FaultCodeValues.INVALID_SIGNATURE, ERROR_MESSAGE);
		assertTrue(reply.isFault());
		try {
			reply.getFlowStatus();
			fail("Should not produce flow status for error responses");
		} catch (Exception e) {
			// OK
		}

		Reply reply1 = factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, "test", null, FaultCodeValues.INVALID_SIGNATURE, ERROR_MESSAGE);
		reply1.setMessageID(reply.getMessageID());
		assertEquals(reply, reply1);

		reply1 = factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, XmlUtil.createNonce(), null, "OTHER FAILURE", ERROR_MESSAGE);
		assertFalse(reply.equals(reply1));
		reply1.setMessageID(reply.getMessageID());
		assertFalse(reply.equals(reply1));
		reply1.setRequestID(reply.getRequestID());
		assertFalse(reply.equals(reply1));

		reply1 = factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, XmlUtil.createNonce(), null, FaultCodeValues.INVALID_SIGNATURE, "OTHER ERROR");
		assertFalse(reply.equals(reply1));
		reply1.setMessageID(reply.getMessageID());
		assertFalse(reply.equals(reply1));
		reply1.setRequestID(reply.getRequestID());
		assertFalse(reply.equals(reply1));

		XmlUtil.createEmptyDocument();
		IDCard idcard = factory.createNewSystemIDCard(
				"test",
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
					AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null,
					factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
		try {
			reply.setIDCard(idcard);
			fail("ID card should not be supported in error replies");
		} catch(ModelException me) {
			// OK. ID-cards not supported in faults.
		}

//		reply = cloneReplyBySerialization(factory, reply);
//
//		Element elmFault = (Element) reply.getBody();
//		assertNotNull(elmFault);
//
//		Element elmFaultCode = (Element) XPathAPI.selectSingleNode(elmFault, SOAPTags.FAULTCODE);
//		assertNotNull(elmFaultCode);
//
//		Element elmMedcomFaultCode = (Element) XPathAPI.selectSingleNode(elmFault, SOAPTags.DETAIL + '/' + MedComTags.FAULT_CODE);
//		assertNotNull(elmMedcomFaultCode);
//
//		Element elmFaultString = (Element) XPathAPI.selectSingleNode(elmFault, SOAPTags.FAULTSTRING);
//		assertNotNull(elmFaultString);
//
//		String strFaultCode = XmlUtil.getTextNodeValue(elmFaultCode);
//		String strMedcomFaultCode = XmlUtil.getTextNodeValue(elmMedcomFaultCode);
//		String strFaultString = XmlUtil.getTextNodeValue(elmFaultString);
//
//		assertTrue("Server".equals(strFaultCode));
//		assertTrue(FaultCodeValues.INVALID_SIGNATURE.equals(strMedcomFaultCode));
//		assertTrue(ERROR_MESSAGE.equals(strFaultString));
	}

	public void testRequestRoundTripUserIDCard() throws Exception {

		// Create a dummy flowId, must be base 64 encoded
		String flowId = XmlUtil.toBase64("flowId".getBytes());

		// Create a SOSI SOAP Request with a self-signed IDCard
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, false, flowId, true);
		Document doc = request.serialize2DOMDocument();

		signatureTest(factory, request, doc);
	}

	public void testRequestRoundTripSystemIDCard() throws Exception {

		// Create a dummy flowId, must be base 64 encoded
		String flowId = XmlUtil.toBase64("flowId".getBytes());

		// Create a SOSI SOAP Request with a self-signed IDCard
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, false, flowId, false);
		Document doc = request.serialize2DOMDocument();
		signatureTest(factory, request, doc);
	}

	public void testReplyRoundTripSystemIDCard() throws Exception {

		// Create a dummy flowId, must be base 64 encoded
		String flowId = XmlUtil.toBase64("flowId".getBytes());

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", flowId, FlowStatusValues.FLOW_RUNNING);

		Document doc = reply.serialize2DOMDocument();
		Element replyForBody = doc.createElement("TestReply");
		reply.setBody(replyForBody);

		// Simulate that the message was written to a pipe and deserialized
		// again on the other side
		byte[] serialXml = XmlUtil.serializeXml2ByteArray(doc, false);

		Reply newReply = factory.deserializeReply(new String(serialXml));

		assertEquals(reply, newReply);
	}

	/**
	 * Sign a document, and validate the signature
	 */
	public void testSignValidate() {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, false, "testflow", true);
		Document doc = request.serialize2DOMDocument();
		Node elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, factory.getFederation(), factory.getCredentialVault(),true))
			fail("Unable to validate signature");
	}

	/**
	 * Check no signature is available on NoAuth security level
	 */
	public void testNoSignatureInNoAuthorisationLevel() {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestNoAuth(factory, false, "testflow", true);
		Document doc = request.serialize2DOMDocument();
		Node elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
		assertNull(elmSignature);
	}

	/**
	 * Check EmptyCredentialVault exceptions
	 */
	public void testEmptyVaultExceptions() {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory(new EmptyCredentialVault());
		try {
			createRequestVOCES(factory, false, "testflow", true);
			fail("CredentialVaultException should be thrown");
		} catch (CredentialVaultException e) {
			// ok
		}
		try {
			createRequestMOCES(factory, false, "testflow");
			fail("CredentialVaultException should be thrown");
		} catch (CredentialVaultException e) {
			// ok
		}
	}

	/**
	 * Test DOM caching and dirty flagging
	 */
	public void testIDCard() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, true, "testflow", false);
		checkDuration(request.getIDCard());
		assertTrue(request.getIDCard().needsSignature);
		assertNull(request.getIDCard().lastDOMOperation);

		// Check that two serializations are entirely equal (incl. ID card
		// serialization)
		Document doc1 = request.serialize2DOMDocument();
		Document doc2 = request.serialize2DOMDocument();
		assertNull(XmlUtil.deepDiff(doc1, doc2));

		// Check implicite signing
		request = createRequestVOCES(factory, true, "testflow", false);
		checkDuration(request.getIDCard());
		doc1 = XmlUtil.createEmptyDocument();
		request.getIDCard().serialize2DOMDocument(factory, doc1);
		assertNull(request.getIDCard().getSignedByCertificate());
		assertTrue(request.getIDCard().needsSignature); // IDCard serialization
		// does not create
		// implicite signature
		doc1 = request.serialize2DOMDocument();
		assertNotNull(request.getIDCard().getSignedByCertificate());
		assertEquals(IDCard.SIGNED, request.getIDCard().lastDOMOperation); // Message
		// serialization
		// should
		// implicitly
		// sign
		// VOCES
		// IDCard

		// Check IDCard node import
		request = createRequestVOCES(factory, true, "testflow", false);
		checkDuration(request.getIDCard());
		doc1 = request.serialize2DOMDocument();
		doc2 = request.serialize2DOMDocument();
		assertFalse(request.getIDCard().needsSignature);
		assertEquals(IDCard.RE_ASSIGNED, request.getIDCard().lastDOMOperation);

		// Check MOCES userIDCard
		Request mocesRequest = createRequestMOCES(factory, false, "testflow");
		checkDuration(mocesRequest.getIDCard());
		assertTrue(mocesRequest.getIDCard().needsSignature);
		assertNull(mocesRequest.getIDCard().lastDOMOperation);
		mocesRequest.serialize2DOMDocument();
		assertTrue(mocesRequest.getIDCard().needsSignature);
		assertEquals(IDCard.CREATED, mocesRequest.getIDCard().lastDOMOperation);
	}

	private void checkDuration(IDCard card) {
		int MAX_IDCARD_LIFE_IN_MS = 24 * 60 * 60 * 1000;
		long diff = card.getExpiryDate().getTime() - card.getCreatedDate().getTime();
		assertTrue(diff <= MAX_IDCARD_LIFE_IN_MS);
	}

	public void testBadIDCards() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		try {
			factory.createNewUserIDCard(
					"testITSystem",
					new UserInfo("012345678", "Jan", "Riis", "jan<at>lakeside.dk", "testOccupation", null, "2101"),
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
					AuthenticationLevel.VOCES_TRUSTED_SYSTEM,
					null,
					null,
					factory	.getCredentialVault().getSystemCredentialPair().getCertificate(),
					null
			);
			fail("Null role should fail");
		} catch (ModelException me) {
			// OK
		}

		try {
			factory.createNewUserIDCard(
					"testITSystem",
					new UserInfo("012345678", "Jan", "Riis", "jan<at>lakeside.dk", "testOccupation", "nurse", "2101"),
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
					null,
					null,
					null,
					factory	.getCredentialVault().getSystemCredentialPair().getCertificate(),
					null
			);
			fail("Null authenticationlevel should fail");
		} catch (ModelException me) {
			// OK
		}

		try {
			factory.createNewUserIDCard("itSystemName", null, new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"), AuthenticationLevel.NO_AUTHENTICATION,
					null, null, null, null);
			fail("Null userinfo should fail");
		} catch (ModelException me) {
			// OK
		}
	}

	// build message, remove saml attribute, validate validator
	public void testMessageTypesForValidAttributes() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		// IDCardData
		checkMissingSamlAttribute(factory, "sosi:IDCardID");
		checkMissingSamlAttribute(factory, "sosi:IDCardVersion");
		checkMissingSamlAttribute(factory, "sosi:IDCardType");
		checkMissingSamlAttribute(factory, "sosi:AuthenticationLevel");
//		checkMissingSamlAttribute(factory, "sosi:OCESCertHash");

		//SystemInfo
		checkMissingSamlAttribute(factory, "medcom:ITSystemName");
		checkMissingSamlAttribute(factory, "medcom:CareProviderID");
		checkMissingSamlAttribute(factory, "medcom:CareProviderName");

		//UserInfo
		checkMissingSamlAttribute(factory, "medcom:UserCivilRegistrationNumber");
		checkMissingSamlAttribute(factory, "medcom:UserGivenName");
		checkMissingSamlAttribute(factory, "medcom:UserSurName");
	}

	private void checkMissingSamlAttribute(SOSIFactory factory, String samlAtt) {
		try {
			// securitytokenrequest
			SecurityTokenRequest request = factory.createNewSecurityTokenRequest();
			SecurityTokenResponse message = factory.createNewSecurityTokenResponse(request);
			UserIDCard idCardWithCpr = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, "0123456789");
			message.setIDCard(idCardWithCpr);

			Document dom = XmlUtil.createEmptyDocument();
			message.serialize2DOMDocument(dom);
			removeSAMLAttribute(dom, samlAtt);
			String xml = XmlUtil.node2String(dom, false, true);
//			System.out.println(xml);
			factory.deserializeSecurityTokenResponse(xml);
			fail("Should fail on "+samlAtt+" missing..");
		} catch (ModelException e) {
			// success
//			System.out.println(samlAtt+": "+e.getMessage());
		} catch (ModelBuildException e) {
			// IDCardVersion parsing
			// success
		} catch (NumberFormatException e) {
			//AuthLevel parsing
			// success
		}
	}

	private void removeSAMLAttribute(Document dom, String samlAtt) {
		NodeList attributes = dom.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, "Attribute");

		for (int i = 0; i < attributes.getLength(); i++) {
            Node elmAttr = attributes.item(i);
			if(samlAtt.equals(elmAttr.getAttributes().item(0).getNodeValue())) {
            	elmAttr.getParentNode().removeChild(elmAttr);
                break;
            }
		}
	}

	public void testRequestsAndResponsesForValidCPR() {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		// userid cards
		// securitytokenrequest
		SecurityTokenRequest streq = factory.createNewSecurityTokenRequest();
		checkCpr(factory, streq, true);

		// securitytokenresponse
		SecurityTokenRequest tokenRequest = factory.createNewSecurityTokenRequest();
		SecurityTokenResponse stresp = factory.createNewSecurityTokenResponse(tokenRequest);
		checkCpr(factory, stresp, false);

		// request
		Request req = factory.createNewRequest(false, "testflow");
		checkCpr(factory, req, false);

		// response
		Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
		checkCpr(factory, reply, false);
	}

	private void checkCpr(SOSIFactory factory, Message message, boolean emptyCprAllowed) {
		UserIDCard idCardWithCpr = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, "0123456789");
		message.setIDCard(idCardWithCpr);
		deserializeMessage(factory, message);
		try {
			UserIDCard idCardWithoutCpr = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, null);
			message.setIDCard(idCardWithoutCpr);
			deserializeMessage(factory, message);
			if(!emptyCprAllowed)
				fail("Should throw ModelException");
		} catch (ModelException e) {}
	}

	private void deserializeMessage(SOSIFactory factory, Message message) {
		Document dom = message.serialize2DOMDocument();
		String xml = XmlUtil.node2String(dom, false, true);
		if(message instanceof Request) factory.deserializeRequest(xml);
		else if(message instanceof Reply) factory.deserializeReply(xml);
		else if(message instanceof SecurityTokenRequest) factory.deserializeSecurityTokenRequest(xml);
		else if(message instanceof SecurityTokenResponse) factory.deserializeSecurityTokenResponse(xml);
	}

	/**
	 * Test serialization into more or less prepared DOM documents.
	 */
	public void testPreparedDOMDocument() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, true, "1234", true);
		Document fromEmptyDoc = req.serialize2DOMDocument();

		Document fromAnotherEmptyDoc = req.serialize2DOMDocument();

		assertNull(XmlUtil.deepDiff(fromEmptyDoc, fromAnotherEmptyDoc));

		Document templateDoc = XmlUtil.createEmptyDocument();
		Element root = templateDoc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
		String checkAttribute = "preparedtest";
		String checkValue = "jriTest";
		root.setAttributeNS(null, checkAttribute, checkValue);
		templateDoc.appendChild(root);

		Document docRoot = (Document) templateDoc.cloneNode(true);
		req.serialize2DOMDocument(docRoot);
		assertTrue("soap:Envelope element was not reused!", docRoot.getDocumentElement().getChildNodes().getLength() > 0);
		assertEquals("soap:Envelope element was replaced!", docRoot.getDocumentElement().getAttribute(checkAttribute), checkValue);

		// Test that already added attributes are left alone
		docRoot = (Document) templateDoc.cloneNode(true);
		Map<String, String> nameSpaces = new HashMap<String, String>(NameSpaces.SOSI_NAMESPACES); // Shallow
		// copy
		// Change one of the namespaces and check that it is left alone
		String someKey = nameSpaces.keySet().iterator().next();
		nameSpaces.put(someKey, "test");
		for (Iterator<String> iter = nameSpaces.keySet().iterator(); iter.hasNext();) {
			String key = iter.next();
			docRoot.getDocumentElement().setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + key, nameSpaces.get(key));
		}
		req.serialize2DOMDocument(docRoot);
		assertEquals(docRoot.getDocumentElement().getAttribute(NameSpaces.NS_XMLNS + ":" + someKey), "test");

		// Test that prepared soap:Header is reused
		Element header = templateDoc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_PREFIXED);
		header.setAttributeNS(null, checkAttribute, checkValue);
		root.appendChild(header);
		Document docHeader = (Document) templateDoc.cloneNode(true);
		req.serialize2DOMDocument(docHeader);
		assertTrue("soap:Header element was not reused!", docHeader.getDocumentElement().getFirstChild().getChildNodes().getLength() > 0);
		assertEquals("soap:Header element was replaced!", checkValue, ((Element) docHeader.getDocumentElement().getFirstChild())
				.getAttribute(checkAttribute));

		// Check that header elements are copied
		Element headerElement = templateDoc.createElementNS(NameSpaces.WSSE_SCHEMA, NameSpaces.NS_WSSE + ":Security");
		header.appendChild(headerElement);
		docHeader = (Document) templateDoc.cloneNode(true);
		req.serialize2DOMDocument(docHeader);
		assertTrue("soap:Header child element was not copied!", docHeader.getDocumentElement().getFirstChild().getChildNodes().item(0)
				.getChildNodes().getLength() > 0);

		// Test that prepared soap:Body is reused
		Element body = templateDoc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_PREFIXED);
		body.setAttributeNS(null, checkAttribute, checkValue);
		root.appendChild(body);
		Document docBody = (Document) templateDoc.cloneNode(true);
		req.serialize2DOMDocument(docBody);
		assertTrue("soap:Header element was not reused!", docBody.getDocumentElement().getFirstChild().getChildNodes().getLength() > 0);
		assertEquals("soap:Body element was replaced!", checkValue, ((Element) docBody.getDocumentElement().getFirstChild())
				.getAttribute(checkAttribute));

		// Test that multiple soap:Header or multiple soap:Body elements
		// triggers an exception
		Document docTemp = (Document) templateDoc.cloneNode(true);
		Element header2 = (Element) docTemp.importNode(header, true);
		docTemp.getDocumentElement().appendChild(header2);
		try {
			req.serialize2DOMDocument(docTemp);
			fail("Multiple soap:Headers did not trigger a DOMBuilderException!");
		} catch (DOMBuilderException dbe) {
			// OK!
		}

        //TODO add namespaces to xml so body can be found
		docTemp = (Document) templateDoc.cloneNode(true);
		Element body2 = (Element) docTemp.importNode(body, true);
		docTemp.getDocumentElement().appendChild(body2);
		try {
			req.serialize2DOMDocument(docTemp);
			fail("Multiple soap:Body did not trigger a DOMBuilderException!");
		} catch (DOMBuilderException dbe) {
			// OK!
		}
	}

	public void testSerializationEquality() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		// Now try with an embedded ID card
		Request request = createRequestVOCES(factory, true, "testflow", false);
		Document reqDom = request.serialize2DOMDocument();
		assertNull(XmlUtil.deepDiff(reqDom, reqDom));
		Document doc = XmlUtil.readXml(properties, XmlUtil.node2String(reqDom, false, true), false);
		Node deepDiff = XmlUtil.deepDiff(reqDom, doc);
		assertNull(deepDiff);
	}

	/**
	 * Replace an IDCard and check that the signature still validates.
	 */
	public void testIDCardReplacement() {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req1 = createRequestVOCES(factory, false, "testflow", true);

		// Validate the ID card signature
		Document doc1 = req1.serialize2DOMDocument();
		Node elmSignature = doc1.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, factory.getFederation(), factory.getCredentialVault(),true))
			fail("Unable to validate signature 1");

		// Create new request on a new document, replace the ID-card and recheck
		// the signature
		Document doc2 = XmlUtil.createEmptyDocument();
		Request req2 = factory.createNewRequest(true, "1234");
		req2.setIDCard(req1.getIDCard());
		req2.setBody(doc2.createElement("test"));
		req2.serialize2DOMDocument(doc2);
		elmSignature = doc2.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, factory.getFederation(), factory.getCredentialVault(),true))
			fail("Unable to validate signature after replacement");

	}

	public void testIDCardSignatureAfterSerialization() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, false, "testflow", true);
		assertTrue(request.getIDCard().needsSignature);
		request.serialize2DOMDocument();
		assertFalse(request.getIDCard().needsSignature);

		Document newDoc = request.serialize2DOMDocument();
		request = factory.deserializeRequest(XmlUtil.node2String(newDoc, false, true));
		assertFalse(request.getIDCard().needsSignature);
	}

	public void testMOCESSignatureNeg() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestMOCES(factory, false, "testflow");
		Document doc = request.serialize2DOMDocument();
		assertTrue(request.getIDCard().needsSignature);

		// Trigger generation of the SignedInfo element
		request.getIDCard().getBytesForSigning(doc);

		// Check negative case first
		try {
			request.getIDCard().injectSignature("bogus signature", factory.getCredentialVault().getSystemCredentialPair().getCertificate());
			fail("injectSignature() should fail on invalid signature");
		} catch (ModelException me) {
			// OK!
		}
	}

	public void testSignedInfoDigests() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestMOCES(factory, false, "testflow");
		Document doc = req.serialize2DOMDocument();

		// Check that there is no digest in the XML
		NodeList digests = doc.getElementsByTagNameNS("ds","DigestValue");
		assertTrue(digests.getLength() == 0);

		// Calculate the digest value from the XML
		String siStr = new String(req.getIDCard().getBytesForSigning(doc));
		String siDigest = siStr.split("\\<ds:DigestValue")[1].split("\\>")[1].split("\\<")[0];

		// Provoke a VOCES signature on the IDCard
		req.getIDCard().needsSignature = true;
		req.getIDCard().domElement = null;
		Document doc1 = req.serialize2DOMDocument();
		req.getIDCard().sign(doc1, factory.getSignatureProvider());

		// Test equality of digests
		digests = doc1.getElementsByTagName("ds:DigestValue");
		assertTrue(digests.getLength() == 1);
		assertEquals(siDigest, XmlUtil.getTextNodeValue(digests.item(0)));
	}

	public void testMOCESSignature() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestMOCES(factory, false, "testflow");
		Document doc = req.serialize2DOMDocument();

		// Check that there is still no digest in the XML
		NodeList digests = doc.getElementsByTagNameNS(NameSpaces.NS_DS, "DigestValue");
		assertTrue(digests.getLength() == 0);

		// Calculate and inject signature
		String signature = createSignature(factory, req, doc);
		req.getIDCard().injectSignature(signature, ((CredentialVaultSignatureProvider) factory.getSignatureProvider()).getCredentialVault().getSystemCredentialPair().getCertificate());

		// Check the signature
		Element signatureParentElement = (Element) XmlUtil.getElementByIdExtended(doc, IDValues.IDCARD);
		NodeList signatures = signatureParentElement.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature");
		if (signatures.getLength() != 1) {
			throw new ModelException("Expected 1 but found " + signatures.getLength() + " SignatureValue elements");
		}
		assertTrue(signatures.getLength() == 1);
		assertTrue(SignatureUtil.validate(signatures.item(0), factory.getFederation(), factory.getCredentialVault(),true));

		// For namespaces already declared in the root element:
		// Re-declaring them or removing extra declarations should not break the signature
		Element samlAssertion = (Element) XPathAPI.selectSingleNode(doc, "//" + SAMLTags.ASSERTION_PREFIXED);
		samlAssertion.removeAttribute("xmlns:saml");
		samlAssertion.removeAttribute("xmlns:ds");
		samlAssertion.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:medcom", NameSpaces.MEDCOM_SCHEMA);
		((Element) samlAssertion.getFirstChild()).setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:ds", NameSpaces.DSIG_SCHEMA);
		assertTrue(SignatureUtil.validate(signatures.item(0), factory.getFederation(), factory.getCredentialVault(), true));

		// Try to tamper the signed IDCard
		Node node = XPathAPI.selectSingleNode(doc, "//saml:Attribute[@Name='medcom:UserAuthorizationCode']/saml:AttributeValue");
		assertNotNull(node);
		node.getFirstChild().setNodeValue("dummy");
		assertFalse(SignatureUtil.validate(signatures.item(0), factory.getFederation(), factory.getCredentialVault(),true));

	}

	public void testInvalidInjectSignature() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestMOCES(factory, false, "testflow");
		Document doc = req.serialize2DOMDocument();

		String signature = createSignature(factory, req, doc);
		try {
			//try to inject the signature together with a different certificate that the one used to sign
			req.getIDCard().injectSignature(signature, CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate());
			fail("Injecting signature together with a different certificate that the one used to sign should fail");
		} catch (ModelException e) {
			// Ok
		}

		try {
			req.getIDCard().injectSignature(signature, null);
			fail("Injecting signature without corresponding certificate should fail");
		} catch (ModelException e) {
			// Ok
		}

	}

	public void testCopyMocesIDCard() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req1 = createRequestMOCES(factory, false, "testflow");
        UserIDCard unsignedIdCard = (UserIDCard) req1.getIDCard();
        unsignedIdCard.sign(req1.serialize2DOMDocument(), factory.getSignatureProvider());
		assertNotNull(unsignedIdCard.getSignedByCertificate());

		Request req2 = createRequestMOCES(factory, false, "testflow");
        UserIDCard signedIdCard = (UserIDCard) factory.copyToVOCESSignedIDCard(unsignedIdCard);
        req2.setIDCard(signedIdCard);
        assertEquals(signedIdCard, req2.getIDCard());

        // Check that req2 is VOCES signed, but has authentication level 4
        assertEquals(AuthenticationLevel.MOCES_TRUSTED_USER, signedIdCard.getAuthenticationLevel());
        assertFalse(signedIdCard.needsSignature);
        assertEquals(IDCard.SIGNED, signedIdCard.lastDOMOperation);
        assertEquals(unsignedIdCard.getUserInfo().getCPR(), signedIdCard.getUserInfo().getCPR());
	}

    public void testCopyMocesIDCardOverwriteCpr() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Request req1 = createRequestMOCES(factory, false, "testflow");
        UserIDCard unsignedIdCard = (UserIDCard) req1.getIDCard();
        unsignedIdCard.sign(req1.serialize2DOMDocument(), factory.getSignatureProvider());
        assertNotNull(unsignedIdCard.getSignedByCertificate());

        String newCpr = "1111111118";

        Request req2 = createRequestMOCES(factory, false, "testflow");
        final UserInfo newUserInfo = new UserInfo(unsignedIdCard.getUserInfo(), newCpr);
        UserIDCard signedIdCard = (UserIDCard) factory.copyToVOCESSignedIdCard(unsignedIdCard, newUserInfo);
        req2.setIDCard(signedIdCard);
        assertEquals(signedIdCard, req2.getIDCard());

        // Check that req2 is VOCES signed, but has authentication level 4
        assertEquals(AuthenticationLevel.MOCES_TRUSTED_USER, signedIdCard.getAuthenticationLevel());
        assertFalse(signedIdCard.needsSignature);
        assertEquals(IDCard.SIGNED, signedIdCard.lastDOMOperation);
        assertEquals(newCpr, signedIdCard.getUserInfo().getCPR());
    }

    public void testCopyMocesIDCardOverwriteUserInfo() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Request req1 = createRequestMOCES(factory, false, "testflow");
        UserIDCard unsignedIdCard = (UserIDCard) req1.getIDCard();
        unsignedIdCard.sign(req1.serialize2DOMDocument(), factory.getSignatureProvider());
        assertNotNull(unsignedIdCard.getSignedByCertificate());

        String newCpr = "1111111118";

        Request req2 = createRequestMOCES(factory, false, "testflow");
        UserInfo newUserInfo = new UserInfo(unsignedIdCard.getUserInfo(), newCpr);
        UserIDCard signedIdCard = (UserIDCard) factory.copyToVOCESSignedIdCard(unsignedIdCard, newUserInfo);
        req2.setIDCard(signedIdCard);
        assertEquals(signedIdCard, req2.getIDCard());

        // Check that req2 is VOCES signed, but has authentication level 4
        assertEquals(AuthenticationLevel.MOCES_TRUSTED_USER, signedIdCard.getAuthenticationLevel());
        assertFalse(signedIdCard.needsSignature);
        assertEquals(IDCard.SIGNED, signedIdCard.lastDOMOperation);
        assertEquals(newCpr, signedIdCard.getUserInfo().getCPR());
        assertNull(signedIdCard.getAlternativeIdentifier());
    }

    public void testCopyUserIDCardOverwriteNameID() {
        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Request req1 = createRequestMOCES(factory, false, "testflow");
        UserIDCard unsignedIdCard = (UserIDCard) req1.getIDCard();
        unsignedIdCard.sign(req1.serialize2DOMDocument(), factory.getSignatureProvider());
        assertNotNull(unsignedIdCard.getSignedByCertificate());

        Request req2 = createRequestMOCES(factory, false, "testflow");
        UserIDCard signedIdCard = (UserIDCard) factory.copyToVOCESSignedIDCard(unsignedIdCard, true);
        req2.setIDCard(signedIdCard);
        assertEquals(signedIdCard, req2.getIDCard());

        // Check that req2 is VOCES signed, but has authentication level 4
        assertEquals(AuthenticationLevel.MOCES_TRUSTED_USER, signedIdCard.getAuthenticationLevel());
        assertFalse(signedIdCard.needsSignature);
        assertEquals(IDCard.SIGNED, signedIdCard.lastDOMOperation);
        assertEquals("SubjectDN={SERIALNUMBER=CVR:30808460-RID:42634739 + CN=TU GENEREL MOCES M CPR gyldig, O=NETS DANID A/S // CVR:30808460, C=DK},IssuerDN={CN=TRUST2408 Systemtest XIX CA, O=TRUST2408, C=DK},CertSerial={1478017446}", signedIdCard.getAlternativeIdentifier());
    }

	public void testCopyExternallySignedIDCard() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req1 = createSecurityTokenRequest(factory, true, false, AuthenticationLevel.MOCES_TRUSTED_USER, "2512484916");
		Document doc = req1.serialize2DOMDocument();
		String signature = createSignature(factory, req1, doc);
		req1.getIDCard().injectSignature(signature, factory.getCredentialVault().getSystemCredentialPair().getCertificate());

		assertNotNull(req1.getIDCard().getSignedByCertificate());
		assertNull(req1.getIDCard().getCertHash());

		Request req2 = createRequestMOCES(factory, false, "testflow");
		req2.setIDCard(factory.copyToVOCESSignedIDCard(req1.getIDCard()));

		assertEquals(req1.getIDCard().getSignedByCertificate(), req2.getIDCard().getSignedByCertificate());
		assertNotNull(req2.getIDCard().getCertHash());
	}

	public void testCopyMocesIDCardWithNewCpr() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest req1 = factory.createNewSecurityTokenRequest();
		UserIDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.MOCES_TRUSTED_USER,
				factory.getCredentialVault().getSystemCredentialPair().getCertificate(), "");
		req1.setIDCard(idCard);

		Document doc = req1.serialize2DOMDocument();
		req1.getIDCard().sign(doc, factory.getSignatureProvider());

		Request req2 = createRequestMOCES(factory, false, "testflow");
        final UserInfo newUserInfo = new UserInfo(((UserIDCard) req1.getIDCard()).getUserInfo(), "0123456789");
		req2.setIDCard(factory.copyToVOCESSignedIdCard((UserIDCard) req1.getIDCard(), newUserInfo));

		// Check that req2 has cpr
		assertEquals("0123456789", ((UserIDCard)req2.getIDCard()).getUserInfo().getCPR());
	}

	public void testCopyVocesIDCard() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req1 = createRequestVOCES(factory, false, "testflow", false);
		Document doc = req1.serialize2DOMDocument();
		req1.getIDCard().sign(doc, factory.getSignatureProvider());

		Request req2 = createRequestMOCES(factory, false, "testflow");

        req2.setIDCard(factory.copyToVOCESSignedIDCard(req1.getIDCard()));

		// Check that req2 is VOCES signed, but has authentication level 3
		assertEquals(AuthenticationLevel.VOCES_TRUSTED_SYSTEM, req2.getIDCard().getAuthenticationLevel());
		assertFalse(req2.getIDCard().needsSignature);
		assertEquals(IDCard.SIGNED, req2.getIDCard().lastDOMOperation);
        assertNull(req2.getIDCard().getAlternativeIdentifier());
    }

    public void testCopyVocesIDCardOverwriteNameID() throws Exception {

        SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
        Request req1 = createRequestVOCES(factory, false, "testflow", false);
        Document doc = req1.serialize2DOMDocument();
        req1.getIDCard().sign(doc, factory.getSignatureProvider());

        Request req2 = createRequestMOCES(factory, false, "testflow");

        req2.setIDCard(factory.copyToVOCESSignedIDCard(req1.getIDCard(), true));

        // Check that req2 is VOCES signed, but has authentication level 3
        assertEquals(AuthenticationLevel.VOCES_TRUSTED_SYSTEM, req2.getIDCard().getAuthenticationLevel());
        assertFalse(req2.getIDCard().needsSignature);
        assertEquals(IDCard.SIGNED, req2.getIDCard().lastDOMOperation);
        assertEquals("SubjectDN={SERIALNUMBER=CVR:30808460-RID:42634739 + CN=TU GENEREL MOCES M CPR gyldig, O=NETS DANID A/S // CVR:30808460, C=DK},IssuerDN={CN=TRUST2408 Systemtest XIX CA, O=TRUST2408, C=DK},CertSerial={1478017446}", req2.getIDCard().getAlternativeIdentifier());
    }

    public void testCopyVocesIDCardOnSTS() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		// without certificate
		SecurityTokenRequest req1 = createSecurityTokenRequestVOCES(factory, false, false);
		Document doc = req1.serialize2DOMDocument();
		assertTrue(XmlUtil.node2String(doc, false, true).indexOf("OCESCertHash") == -1);
		req1.getIDCard().sign(doc, factory.getSignatureProvider());
		assertTrue(XmlUtil.node2String(doc, false, true).indexOf("OCESCertHash") == -1);

		SecurityTokenResponse resp1 = factory.createNewSecurityTokenResponse(req1);
		// the copyToVoces should add certhash
		resp1.setIDCard(factory.copyToVOCESSignedIDCard(req1.getIDCard()));

		assertNotNull(resp1.getIDCard().getCertHash());
		// Check that resp1 is VOCES signed, but has authentication level 3
		assertEquals(AuthenticationLevel.VOCES_TRUSTED_SYSTEM, resp1.getIDCard().getAuthenticationLevel());
		assertFalse(resp1.getIDCard().needsSignature);
		assertEquals(IDCard.SIGNED, resp1.getIDCard().lastDOMOperation);
		assertTrue(XmlUtil.node2String(resp1.serialize2DOMDocument(), false, true).indexOf("OCESCertHash") != -1);
	}

	public void testMOCESAuthenticationLevel() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestMOCES(factory, false, "testflow");
		assertEquals(AuthenticationLevel.MOCES_TRUSTED_USER, req.getIDCard().getAuthenticationLevel());

		Document doc = req.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);

		// Deserializing an ID card with no signature should result in an
		// exception
		try {
			factory.deserializeRequest(xml);
			fail("Deserializing an ID card with no signature should result in an exception");
		} catch (SignatureInvalidModelBuildException simbe) {
			assertEquals(req.getFlowID(), simbe.getFlowID());
			assertEquals(req.getMessageID(), simbe.getMessageID());
		}

		// Calculate and inject signature
		String signature = createSignature(factory, req, doc);
		req.getIDCard().injectSignature(signature, ((CredentialVaultSignatureProvider) factory.getSignatureProvider()).getCredentialVault().getSystemCredentialPair().getCertificate());
		doc = req.serialize2DOMDocument();
		xml = XmlUtil.node2String(doc, false, true);
		req = factory.deserializeRequest(xml);
		assertEquals(AuthenticationLevel.MOCES_TRUSTED_USER, req.getIDCard().getAuthenticationLevel());
	}

	public void testVOCESAuthenticationLevelUser() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, true, "testflow", true);
		Document doc = req.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);
		req = factory.deserializeRequest(xml);
		assertEquals(AuthenticationLevel.VOCES_TRUSTED_SYSTEM, req.getIDCard().getAuthenticationLevel());
	}

	public void testVOCESAuthenticationLevelSystem() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, "testflow", false);
		req = cloneRequestBySerialization(factory, req);
		assertEquals(AuthenticationLevel.VOCES_TRUSTED_SYSTEM, req.getIDCard().getAuthenticationLevel());
	}

	public void testNoAuthenticationLevelSystem() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestNoAuth(factory, false, "testflow", false);
		req = cloneRequestBySerialization(factory, req);
		assertEquals(AuthenticationLevel.NO_AUTHENTICATION, req.getIDCard().getAuthenticationLevel());
	}

	public void testNoAuthenticationLevelUser() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestNoAuth(factory, false, "testflow", true);
		req = cloneRequestBySerialization(factory, req);
		assertEquals(AuthenticationLevel.NO_AUTHENTICATION, req.getIDCard().getAuthenticationLevel());
	}

	public void testNoAuthenticationLevelSystemWithEmptyVault() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory(new EmptyCredentialVault());
		Request req = createRequestNoAuth(factory, false, "testflow", false);
		req = cloneRequestBySerialization(factory, req);
		assertEquals(AuthenticationLevel.NO_AUTHENTICATION, req.getIDCard().getAuthenticationLevel());
	}

	public void testNoAuthenticationLevelUserWithEmptyVault() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory(new EmptyCredentialVault());
		Request req = createRequestNoAuth(factory, false, "testflow", true);
		req = cloneRequestBySerialization(factory, req);
		assertEquals(AuthenticationLevel.NO_AUTHENTICATION, req.getIDCard().getAuthenticationLevel());
	}

	public void testAuthenticationLevelNeg() throws Exception {

		try {
			AuthenticationLevel.getEnumeratedValue(10);
			fail("getEnumeratedValue should fail on invalid level");
		} catch (ModelException me) {
			// OK
		}
	}

	public void testMessageEquals() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, "testflow", false);
		checkBasicEquals(req);

		Request reqClone = cloneRequestBySerialization(factory, req);
		assertEquals(req, reqClone);

		reqClone.setCreationDate(new Date(System.currentTimeMillis() + 2000));
		assertFalse(req.equals(reqClone));

		Request reqTemp = createRequestVOCES(factory, false, "testflow", false);
		reqClone = cloneRequestBySerialization(factory, req);
		assertEquals(req, reqClone);
		reqClone.setIDCard(reqTemp.getIDCard());
		assertFalse(req.equals(reqClone));

		reqClone = cloneRequestBySerialization(factory, req);
		assertEquals(req, reqClone);
		reqClone.setFlowID("bogusFlow");
		assertFalse(req.equals(reqClone));

		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
		IDCard idCard = factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null,
				factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);

		SecurityTokenRequest securityTokenRequest = factory.createNewSecurityTokenRequest();
		securityTokenRequest.setIDCard(idCard);
		SecurityTokenRequest securityTokenRequestClone = cloneSecurityTokenRequestBySerialization(factory, securityTokenRequest);
		assertEquals(securityTokenRequest, securityTokenRequestClone);

		SecurityTokenResponse securityTokenResponse = factory.createNewSecurityTokenResponse(securityTokenRequest);
		securityTokenResponse.setIDCard(idCard);
		SecurityTokenResponse securityTokenResponseClone = cloneSecurityTokenResponseBySerialization(factory, securityTokenResponse);
		assertEquals(securityTokenResponse, securityTokenResponseClone);

	}

	public void testReplyEquals() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Reply reply = factory.createNewReply(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, "inResponseToID", "flowID", FlowStatusValues.FLOW_RUNNING);
		checkBasicEquals(reply);

		// Test requestID
		Reply clonedReply = cloneReplyBySerialization(factory, reply);
		assertEquals(reply, clonedReply);
		clonedReply.setRequestID("bogus");
		assertFalse(reply.equals(clonedReply));

		// Test flow status
		clonedReply = cloneReplyBySerialization(factory, reply);
		clonedReply.setFlowStatus("bogus");
		assertFalse(reply.equals(clonedReply));
	}

	public void testIDCardEquals() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, "testflow", false);
		IDCard idcard = req.getIDCard();
		checkBasicEquals(idcard);

		Document doc = req.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);
		assertEquals(idcard, factory.deserializeRequest(xml).getIDCard());
	}

	public void testIDCardNullID() throws Exception {

		try {
			new IDCard(null, null, null, AuthenticationLevel.MOCES_TRUSTED_USER, "certhash", "issuer", new Date(), new Date(), null, null, null) {
				private static final long serialVersionUID = 1612456955426243414L;
			};
			fail("Should fail on null ID");
		} catch (ModelException me) {
			// OK!
		}
	}

	public void testIDCardTimeValidity() throws Exception {
		// Positive test
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, "testflow", false);
		assertTrue(req.getIDCard().isValidInTime());

		// Negative test
		req = createRequestNoAuth(factory, false, "testflow",true);
		Document doc = req.serialize2DOMDocument();

		// Test past condition interval
		Element pastConditionElement = createCondition(doc,25*HOUR_IN_MILLIS, factory);
		// replace condition element <saml:Conditions NotBefore="2007-02-22T15:41:54" NotOnOrAfter="2007-02-23T15:41:54" />
		req = replaceCondition(factory, doc,pastConditionElement);
		assertFalse(req.getIDCard().isValidInTime());

		// Test future condition element
		doc = req.serialize2DOMDocument();
		Element futureConditionElement = createCondition(doc,-HOUR_IN_MILLIS, factory); // Future startdate
		req = replaceCondition(factory, doc,futureConditionElement);
		assertFalse(req.getIDCard().isValidInTime());

		// Test transition cases: future
		doc = req.serialize2DOMDocument();

		int s = 5000; 	// max seconds to try
		int t = 200;		// number of milliseconds to move the validity period
		int max = (int)Math.ceil((-0.5+Math.sqrt(0.25+2*s/t))); // Calculate max number of tries before skipping the test

		int i=1;
		for(;i<max; i++) { // try only up to s milliseconds, otherwise warn and skip this test
			futureConditionElement = createCondition(doc,-i*t, factory); // Startdate in near future
			req = replaceCondition(factory, doc,futureConditionElement);
			if(!req.getIDCard().isValidInTime())
				break;
		}
		if(i==max) {
			System.out.println("Warning: startdate border transition was not tested!");
		} else {
			Thread.sleep(i*t);
			assertTrue(req.getIDCard().isValidInTime());
		}
		// Test transition cases: past
		doc = req.serialize2DOMDocument();
		 i=1;
		for(;i<max; i++) { // try only up to 10 seconds otherwise warn and skip this test
			futureConditionElement = createCondition(doc,24*HOUR_IN_MILLIS-i*t, factory); // Expirydate in near future
			req = replaceCondition(factory, doc,futureConditionElement);
			if(req.getIDCard().isValidInTime())
				break;
		}
		if(i==max) {
			System.out.println("Warning: expirery border transition was not tested!");
		} else {
			Thread.sleep(i*t);
			assertFalse(req.getIDCard().isValidInTime());
		}
	}

	public void testIDCardNotPrepared() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, "testflow", false);
		assertNull(req.getIDCard().domElement);
		try {
			req.getIDCard().sign(XmlUtil.createEmptyDocument(), factory.getSignatureProvider());
			fail("sign() should fail if the id card has no DOM element attached");
		} catch (IllegalStateException ise) {
			// OK!
		}

		try {
			req.getIDCard().injectSignature("test", ((CredentialVaultSignatureProvider) factory.getSignatureProvider()).getCredentialVault().getSystemCredentialPair().getCertificate());
			fail("injectSignature() should fail if the id card has no DOM element attached");
		} catch (ModelException ise) {
			// OK!
		}

	}

	public void testIDCardVersion() throws Exception {
		SOSIFactory factory = new SOSIFactory(new EmptyCredentialVault(), new Properties());
		IDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.MOCES_TRUSTED_USER, null, "1111111118");
		assertEquals(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, idCard.getVersion());
		idCard = createNewSystemIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION);
		assertEquals(SOSIFactory.SOSI_DEFAULT_DGWS_VERSION, idCard.getVersion());

		Properties properties = new Properties();
		properties.put(SOSIFactory.PROPERTYNAME_SOSI_DGWS_VERSION, "1.0");
		factory = new SOSIFactory(new EmptyCredentialVault(), properties);
		idCard = createNewUserIdCard(factory, AuthenticationLevel.MOCES_TRUSTED_USER, null, "1111111118");
		assertEquals("1.0", idCard.getVersion());
		idCard = createNewSystemIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION);
		assertEquals("1.0", idCard.getVersion());

		try {
			SystemInfo systemInfo = new SystemInfo(new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "SomeOrg"), "ItSystem");
			new SystemIDCard(null, AuthenticationLevel.NO_AUTHENTICATION, "issuer", systemInfo, null, null, null, null);
			fail("Should fail on empyt/null parameter");
		} catch (ModelException me) {
			// OK
		}

		try {
			SystemInfo systemInfo = new SystemInfo(new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "SomeOrg"), "ItSystem");
			new SystemIDCard(null, null, "1234", AuthenticationLevel.NO_AUTHENTICATION, null, "issuer", systemInfo, new Date(), new Date(), null, null, null);
			fail("Should fail on empyt/null parameter");
		} catch (ModelException me) {
			// OK
		}

		try {
			SystemInfo systemInfo = new SystemInfo(new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "SomeOrg"), "ItSystem");
			new SystemIDCard("X.Y.Z", AuthenticationLevel.NO_AUTHENTICATION, "issuer", systemInfo, null, null, null, null);
			fail("Should fail on unsupported version");
		} catch (ModelException me) {
			// OK
		}

		try {
			SystemInfo systemInfo = new SystemInfo(new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "SomeOrg"), "ItSystem");
			new SystemIDCard("X.Y.Z", null, "1234", AuthenticationLevel.NO_AUTHENTICATION, null, "issuer", systemInfo, new Date(), new Date(), null, null, null);
			fail("Should fail on unsupported version");
		} catch (ModelException me) {
			// OK
		}

	}

	public void testSystemInfo() throws Exception {

		try {
			new SystemInfo(null, "");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException me) {
			// OK
		}

		try {
			new SystemInfo(new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"), null);
			fail("Should fail on empyt/null parameter");
		} catch (ModelException me) {
			// OK
		}

		try {
			new SystemInfo(new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"), "");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException me) {
			// OK
		}
	}

	public void testUserInfo() throws Exception {
		UserInfo info1 = new UserInfo("1234", "Hans", "Hansen", "hans@hansen.dk", "læge", "praktiserende læge", "1234");
		UserInfo info2 = new UserInfo("1234", "Hans", "Hansen", "hans@hansen.dk", "et eller andet stilling", "praktiserende læge", "1234");
		assertFalse(info1.equals(info2));

		UserInfo userInfo = new UserInfo(null, "Hans", "Hansen", "hans@hansen.dk", "læge", "praktiserende læge", "1234");
		assertEquals("", userInfo.getCPR());

		try {
			new UserInfo("1234", null, "Hansen", "hans@hansen.dk", "læge", "praktiserende læge", "1234");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new UserInfo("1234", "", "Hansen", "hans@hansen.dk", "læge", "praktiserende læge", "1234");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new UserInfo("1234", "Hans", null, "hans@hansen.dk", "læge", "praktiserende læge", "1234");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new UserInfo("1234", "Hans", "", "hans@hansen.dk", "læge", "praktiserende læge", "1234");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new UserInfo("1234", "Hans", "Hansen", "hans@hansen.dk", "læge", null, "1234");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new UserInfo("1234", "Hans", "Hansen", "hans@hansen.dk", "læge", "", "1234");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}

		new UserInfo(null, "Hans", "Hansen", null, null, "Praktiserende læge", null);

	}

	public void testCareProvider() throws Exception {
		try {
			new CareProvider(null,"1234", "Sygehusafdeling");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider("","1234", "Sygehusafdeling");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider(SubjectIdentifierTypeValues.SKS_CODE, null, "Sygehusafdeling");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider(SubjectIdentifierTypeValues.SKS_CODE, "", "Sygehusafdeling");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider(SubjectIdentifierTypeValues.SKS_CODE, "1234", null);
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider(SubjectIdentifierTypeValues.SKS_CODE, "1234", "");
			fail("Should fail on empyt/null parameter");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider("SomeCareProviderType","1234", "Sygehusafdeling");
			fail("Should fail on unknown CareProviderType");
		} catch (ModelException e) {
			//ok
		}
		try {
			new CareProvider(SubjectIdentifierTypeValues.CPR_NUMBER,"1234", "Sygehusafdeling");
			fail("Should fail on unknown CareProviderType");
		} catch (ModelException e) {
			//ok
		}

		new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "Organisation XYZ");
		new CareProvider(SubjectIdentifierTypeValues.SKS_CODE, "1234", "Sygehusafdelingen 123");
		new CareProvider(SubjectIdentifierTypeValues.Y_NUMBER, "1234", "Læge Hansen");
		new CareProvider(SubjectIdentifierTypeValues.P_NUMBER, "1234", "Et eller andet organisation");

	}

	public void testNullFlowID() throws Exception {

		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request req = createRequestVOCES(factory, false, null, false);
		assertNull(req.getFlowID());
		// Check that a serialization/deserialization does not break due to a
		// missing flow ID
		req = cloneRequestBySerialization(factory, req);
		assertNull(req.getFlowID());
	}

	public void testSerializeUserOccupation() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		UserIDCard idCard = createNewUserIdCard(factory, AuthenticationLevel.NO_AUTHENTICATION, null, "1234567890");
		Element doc = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		UserIDCard deserializedIDCard = (UserIDCard) factory.deserializeIDCard(XmlUtil.node2String(doc));
		assertEquals(idCard, deserializedIDCard);
		assertEquals(idCard.getUserInfo(), deserializedIDCard.getUserInfo());
		assertEquals(idCard.getUserInfo().getOccupation(), deserializedIDCard.getUserInfo().getOccupation());
	}

	public void testSerializeMinimalIDCard() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "SomeOrg");
		UserInfo userInfo = new UserInfo(null, "Hans", "Hansen", null, null, "Praktiserende læge", null);

		UserIDCard idCard = factory.createNewUserIDCard("EMS/Harmoni", userInfo, careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, "1234");
		Element element = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		String xml = XmlUtil.node2String(element, true, true);
		UserIDCard deserializedIDCard = (UserIDCard) factory.deserializeIDCard(xml);
		assertEquals(idCard, deserializedIDCard);

		userInfo = new UserInfo("1234", "Hans", "Hansen", null, null, "Praktiserende læge", null);
		idCard = factory.createNewUserIDCard("EMS/Harmoni", userInfo, careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
		element = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(element, true, true);
		deserializedIDCard = (UserIDCard) factory.deserializeIDCard(xml);
		assertEquals(idCard, deserializedIDCard);

	}

	/*
	public void testDeserializeIDCardWithEmptyAttributes() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "SomeOrg");
		UserInfo userInfo = new UserInfo(null, "Hans", "Hansen", "hans@email.com", null, "Praktiserende læge", null);

		UserIDCard idCard = factory.createNewUserIDCard("EMS/Harmoni", userInfo, careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, "1234");
		Element element = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		String xml = XmlUtil.node2String(element, true, true);
		//xml = xml.replaceFirst("<saml:AttributeValue>hans@email.com</saml:AttributeValue>", "");
		xml = xml.replaceFirst("hans@email.com", "");
		System.out.println(xml);
		UserIDCard deserializedIDCard = (UserIDCard) factory.deserializeIDCard(xml);

	}
	*/

	public void testDeserializeSecurityTokenRequestEmptyCPR() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		SecurityTokenRequest request = createSecurityTokenRequest(factory, true, false, AuthenticationLevel.MOCES_TRUSTED_USER, null);
		Document doc = request.serialize2DOMDocument();
		String signature = createSignature(factory, request, doc);
		request.getIDCard().injectSignature(signature, factory.getCredentialVault().getSystemCredentialPair().getCertificate());
		String xml = XmlUtil.node2String(doc);
		SecurityTokenRequest deserializedRequest = factory.deserializeSecurityTokenRequest(xml);
		assertEquals(request, deserializedRequest);
	}

	public void testDeserializeRequestHeader() throws Exception {
		if (System.getProperty("java.specification.version").equals("1.4")) {
			System.out.println("'testDeserializeRequestHeader' disabled on jdk 1.4 due to insufficient handling of namespaces in the version of Xalan shipped with the jdk.");
			return;
		}
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		Request request = createRequestVOCES(factory, true, "1234", true);
		Document doc = request.serialize2DOMDocument();
		Element headerNode = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
		String xml = XmlUtil.node2String(headerNode);
		RequestHeader header = factory.deserializeRequestHeader(xml);

		assertNotNull(header);
		assertEquals(xml, XmlUtil.node2String(header.getDocument()));
		assertEquals(request.getIDCard(), header.getIDCard());
		assertEquals(request.getMessageID(), header.getMessageID());
		// milliseconds are not serialized - ignore them!
		assertEquals(Math.abs(request.getCreationDate().getTime() / 1000), Math.abs(header.getCreationDate().getTime() / 1000));
		assertEquals(request.getDGWSVersion(), header.getDGWSVersion());
		assertEquals(request.getFlowID(), header.getFlowID());
		assertEquals(request.isDemandNonRepudiationReceipt(), header.isDemandNonRepudiationReceipt());
	}

	public void testDeserializeReplyHeader() throws Exception {
		if (System.getProperty("java.specification.version").equals("1.4")) {
			System.out.println("'testDeserializeReplyHeader' disabled on jdk 1.4 due to insufficient handling of namespaces in the version of Xalan shipped with the jdk.");
			return;
		}
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, true, "1234", true);

		Reply reply = factory.createNewReply(request, FlowStatusValues.FLOW_FINALIZED_SUCCESFULLY);
		reply.setIDCard(request.getIDCard());
		Document doc = reply.serialize2DOMDocument();
		Element headerNode = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
		String xml = XmlUtil.node2String(headerNode);
		ReplyHeader header = factory.deserializeReplyHeader(xml);

		assertNotNull(header);
		assertEquals(xml, XmlUtil.node2String(header.getDocument()));
		assertEquals(reply.getIDCard(), header.getIDCard());
		assertEquals(reply.getMessageID(), header.getMessageID());
		// milliseconds are not serialized - ignore them!
		assertEquals(Math.abs(reply.getCreationDate().getTime() / 1000), Math.abs(header.getCreationDate().getTime() / 1000));
		assertEquals(reply.getDGWSVersion(), header.getDGWSVersion());
		assertEquals(reply.getFlowID(), header.getFlowID());
		assertEquals(reply.getFlowStatus(), header.getFlowStatus());
		assertEquals(reply.getRequestID(), header.getRequestID());

		reply = factory.createNewErrorReply(request, "faultCode", "faultString");
		doc = reply.serialize2DOMDocument();
		headerNode = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
		xml = XmlUtil.node2String(headerNode);

		try {
			factory.deserializeReplyHeader(xml);
			fail("Excpected ModelBuildException when deserialixing header from error reply");
		} catch (ModelBuildException e) {
			// Expected
		}
	}

	public void testRequestWithoutNonRepudiation() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestNoAuth(factory, true, null, false);
		Document doc = request.serialize2DOMDocument();
		Node nonRepudiationNode = doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, "RequireNonRepudiationReceipt").item(0);
		nonRepudiationNode.getParentNode().removeChild(nonRepudiationNode);
		String xml = XmlUtil.node2String(doc);
		Request deserializedRequest = factory.deserializeRequest(xml);
		assertFalse(deserializedRequest.isDemandNonRepudiationReceipt());
	}

    public void __testCertificateReference() {
        CredentialVault credentialVault = CredentialVaultTestUtil.getVocesCredentialVault();
        System.out.println(credentialVault.getSystemCredentialPair().getCertificate());

        Properties props = SignatureUtil.setupCryptoProviderForJVM();
        props.put(SOSIFactory.PROPERTYNAME_SOSI_VALIDATE, "false");
        props.put(SOSIFactory.PROPERTYNAME_SOSI_ISSUER, "SOSI");
        props.put("sosi:federationcertificate.host.oces1", "dir.certifikat.dk");

        // Get the factory
        Federation sosiTestFederation = new SOSITestFederation(props, new HashMapCertificateCache());
        SOSIFactory factory = new SOSIFactory(sosiTestFederation, credentialVault,  props);

        final SystemIDCard idCard = createNewSystemIdCard(factory, AuthenticationLevel.VOCES_TRUSTED_SYSTEM);
        final SecurityTokenRequest request = factory.createNewSecurityTokenRequest();
        request.setIDCard(idCard);
        Document document = request.serialize2DOMDocument();

        System.out.println(XmlUtil.node2String(document, true, false));

        // udskift KeyInfo

        String nsSoap = "http://schemas.xmlsoap.org/soap/envelope/";
        String nsWst = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        String nsSaml = "urn:oasis:names:tc:SAML:2.0:assertion";
        String nsDs = "http://www.w3.org/2000/09/xmldsig#";

        Element soapEnv = document.getDocumentElement();
        Element body = XmlUtil.getFirstChildElementNS(soapEnv, nsSoap, "Body");
        Element rst = XmlUtil.getFirstChildElementNS(body, nsWst, "RequestSecurityToken");
        Element claims = XmlUtil.getFirstChildElementNS(rst, nsWst, "Claims");
        Element assertion = XmlUtil.getFirstChildElementNS(claims, nsSaml, "Assertion");
        Element sig = XmlUtil.getFirstChildElementNS(assertion, nsDs, "Signature");

        Element keyInfo = XmlUtil.getFirstChildElementNS(sig, nsDs, "KeyInfo");

        Element x509Data = XmlUtil.getFirstChildElementNS(keyInfo, nsDs, "X509Data");
        keyInfo.removeChild(x509Data);

        Element keyName = document.createElementNS(nsDs, "KeyName");
        keyName.appendChild(document.createTextNode("OCES2,CVR:55832218-UID:1165408969529,1077391241"));
        keyInfo.appendChild(keyName);

        final String xmlString = XmlUtil.node2String(document);
        factory.deserializeSecurityTokenRequest(xmlString);
    }


	// ==========================================
	// Helpers
	// ==========================================

	private Request createRequestNoAuth(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard) {
		return createRequest(factory, nonRep, flowID, userIDCard, AuthenticationLevel.NO_AUTHENTICATION);
	}

	private Request createRequestVOCES(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard) {
		return createRequest(factory, nonRep, flowID, userIDCard, AuthenticationLevel.VOCES_TRUSTED_SYSTEM);
	}

	private Request createRequestMOCES(SOSIFactory factory, boolean nonRep, String flowID) {
		return createRequest(factory, nonRep, flowID, true, AuthenticationLevel.MOCES_TRUSTED_USER);
	}

	private Request createRequest(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard, AuthenticationLevel authLevel) {
		return createRequest(factory, nonRep, flowID, userIDCard, authLevel, "1234567890");
	}

	private Request createRequest(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard, AuthenticationLevel authLevel, String cpr) {

		Request request = factory.createNewRequest(nonRep, flowID);

		X509Certificate certificate = null;
		if(!AuthenticationLevel.NO_AUTHENTICATION.equals(authLevel)) {
			certificate = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		}

		if (userIDCard) {
			request.setIDCard(createNewUserIdCard(factory, authLevel, certificate,cpr));
		} else {
			request.setIDCard(factory.createNewSystemIDCard(
					"testITSystem",
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER,
					"124454",
					"Hansens Praksis"),
					authLevel,
					null,
					null,
					certificate,
					null));
		}
		return request;
	}

	private SecurityTokenRequest createSecurityTokenRequestVOCES(SOSIFactory factory, boolean userIDCard, boolean certificate) {
		return createSecurityTokenRequest(factory, userIDCard, certificate, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, "1234567890");
	}

	private SecurityTokenRequest createSecurityTokenRequest(SOSIFactory factory, boolean userIDCard, boolean certificate, AuthenticationLevel authLevel, String cpr) {

		SecurityTokenRequest request = factory.createNewSecurityTokenRequest();

		X509Certificate cert = null;
		if(certificate && !AuthenticationLevel.NO_AUTHENTICATION.equals(authLevel)) {
			cert = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		}

		if (userIDCard) {
			request.setIDCard(createNewUserIdCard(factory, authLevel, cert,cpr));
		} else {
			request.setIDCard(factory.createNewSystemIDCard(
					"testITSystem",
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER,
					"124454",
					"Hansens Praksis"),
					authLevel,
					null,
					null,
					cert,
					null));
		}
		return request;
	}

	private UserIDCard createNewUserIdCard(SOSIFactory factory, AuthenticationLevel authLevel, X509Certificate certificate, String cpr) {
		return factory.createNewUserIDCard(
				"testITSystem",
				new UserInfo(cpr, "Jan", "Riis", "jan<at>lakeside.dk", "hacker", "doctor", "2101"),
				new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
				authLevel,
				null,
				null,
				certificate,
				null);
	}

	private SystemIDCard createNewSystemIdCard(SOSIFactory factory, AuthenticationLevel authLevel) {
		return factory.createNewSystemIDCard(
				"testITSystem",
				new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
				authLevel,
				null,
				null,
				null,
				null);
	}

	private void signatureTest(SOSIFactory factory, Request request, Document doc) throws ModelBuildException {

		// Validate the signature
		Node signature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
		assertNotNull(signature);

		if (!SignatureUtil.validate(signature, factory.getFederation(), factory.getCredentialVault(),true))
			fail("Failed to validate signature?!");

		// Simulate that the message was written to a pipe and deserialized
		// again on the other side
		String serialXml = XmlUtil.node2String(doc, false, true);
		doc = XmlUtil.readXml(properties, serialXml, true);

		signature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(signature, factory.getFederation(), factory.getCredentialVault(),true))
			fail("Unable to validate signature after serialization & deserialization");

		Request newRequest = factory.deserializeRequest(new String(serialXml));

		assertEquals(request, newRequest);
	}

	private String createSignature(SOSIFactory factory, Message req1, Document doc) throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		byte[] siBytes = req1.getIDCard().getBytesForSigning(doc);
		// Sign the bytes with a private key (in this case the key in credential
		// vault, but that makes no difference)
		Signature jceSign;
		try {
			jceSign = Signature.getInstance("SHA1withRSA",SignatureUtil.getCryptoProvider(factory.getProperties(),
					SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA));
		} catch (NoSuchProviderException e) {
			throw new ModelException("No Such Provider", e);
		}
		PrivateKey key = factory.getCredentialVault().getSystemCredentialPair().getPrivateKey();
		jceSign.initSign(key);
		jceSign.update(siBytes);
		String signature = XmlUtil.toBase64(jceSign.sign());
		return signature;
	}

	private Request cloneRequestBySerialization(SOSIFactory factory, Request req) throws ModelBuildException {

		Document doc = req.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);
		return factory.deserializeRequest(xml);
	}

	private Reply cloneReplyBySerialization(SOSIFactory factory, Reply rep) throws ModelBuildException {

		Document doc = rep.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);
		return factory.deserializeReply(xml);
	}

	private SecurityTokenRequest cloneSecurityTokenRequestBySerialization(SOSIFactory factory, SecurityTokenRequest securityTokenRequest)
			throws ModelBuildException {

		Document doc = securityTokenRequest.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);
		return factory.deserializeSecurityTokenRequest(xml);
	}

	private SecurityTokenResponse cloneSecurityTokenResponseBySerialization(SOSIFactory factory, SecurityTokenResponse securityTokenResponse)
			throws ModelBuildException {

		Document doc = securityTokenResponse.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);
		return factory.deserializeSecurityTokenResponse(xml);
	}

	private void checkBasicEquals(Object object) {

		assertNotNull(object);
		assertFalse(object.equals(new Object()));
		assertTrue(object.equals(object));
	}

	private Element createCondition(Document doc, long  subtractMillis, SOSIFactory factory) {
		Element newCondition = doc.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.CONDITIONS_PREFIXED);
		long now = System.currentTimeMillis();
		Date invalidStartDate = new Date(now-subtractMillis);
		Date endDate = new Date(now-subtractMillis+24*HOUR_IN_MILLIS);
        boolean useZuluTime = true;
		newCondition.setAttributeNS(null, SAMLAttributes.NOT_BEFORE, XmlUtil.toXMLTimeStamp(invalidStartDate, useZuluTime));
		newCondition.setAttributeNS(null, SAMLAttributes.NOT_ON_OR_AFTER, XmlUtil.toXMLTimeStamp(endDate, useZuluTime));
		return newCondition;
	}

	private Request replaceCondition(SOSIFactory factory, Document doc, Element pastConditionElement) {
		Element condition =  XmlUtil.selectSingleElement(doc, "//"+SAMLTags.CONDITIONS_PREFIXED, new ModelPrefixResolver(), true);
		condition.getParentNode().replaceChild(pastConditionElement, condition);
		// Deserialize document and check validity
		return factory.deserializeRequest(XmlUtil.node2String(doc));
	}
}
