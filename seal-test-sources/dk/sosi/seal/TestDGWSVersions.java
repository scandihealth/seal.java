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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/TestDGWSVersions.java $
 * $Id: TestDGWSVersions.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */

package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.modelbuilders.ModelPrefixResolver;
import dk.sosi.seal.modelbuilders.SignatureInvalidModelBuildException;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.text.ParseException;
import java.util.Date;
import java.util.Properties;

/**
 * @author chg
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 33209 $
 * @since 1.0
 */
public class TestDGWSVersions extends TestCase {

	private static final int DELTA = 5000;
	private static final int FIVE_MINUTES = 5 * 60 * 1000;
	private static final int TWENTYFOUR_HOURS = 24 * 60 * 60 * 1000;

	public void testZuluTime() throws Exception {
		timeTest(DGWSConstants.VERSION_1_0_1, true);
	}

	public void testLocalTime() throws Exception {
		timeTest(DGWSConstants.VERSION_1_0, false);
	}

	private void timeTest(String version, boolean isZuluTimeFormat) throws ParseException {
		Properties properties = new Properties();
		properties.put(SOSIFactory.PROPERTYNAME_SOSI_DGWS_VERSION, version);
		SOSIFactory factory = new SOSIFactory(new EmptyCredentialVault(), properties);

		Request request = factory.createNewRequest(false, "flowID");
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "1234", "someOrg");
		IDCard idCard = factory.createNewSystemIDCard("ItSystem", careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
		request.setIDCard(idCard);

		Document doc = request.serialize2DOMDocument();
		Element createdTime = XmlUtil.selectSingleElement(doc, "//" + NameSpaces.NS_WSU + ":Created", new ModelPrefixResolver(), true);
		assertEquals(isZuluTimeFormat, createdTime.getFirstChild().getNodeValue().endsWith("Z"));
		Date parsedDate = XmlUtil.fromXMLTimeStamp(createdTime.getFirstChild().getNodeValue());
		assertTrue(Math.abs(parsedDate.getTime() - System.currentTimeMillis()) < DELTA);

		Element samlAssertion = XmlUtil.selectSingleElement(doc, "//" + SAMLTags.ASSERTION_PREFIXED, new ModelPrefixResolver(), true);
		String issueInstant = samlAssertion.getAttribute(SAMLAttributes.ISSUE_INSTANT);
		assertEquals(isZuluTimeFormat, createdTime.getFirstChild().getNodeValue().endsWith("Z"));
		parsedDate = XmlUtil.fromXMLTimeStamp(issueInstant);
		// IssueInstant is set to five minutes before 'now'
		assertTrue(Math.abs(parsedDate.getTime() - System.currentTimeMillis() + FIVE_MINUTES) < DELTA);

		Element samlConditions = XmlUtil.selectSingleElement(doc, "//" + SAMLTags.CONDITIONS_PREFIXED, new ModelPrefixResolver(), true);
		String notBefore = samlConditions.getAttribute(SAMLAttributes.NOT_BEFORE);
		assertEquals(isZuluTimeFormat, createdTime.getFirstChild().getNodeValue().endsWith("Z"));
		parsedDate = XmlUtil.fromXMLTimeStamp(notBefore);
		// NotBefore is set to five minutes before 'now'
		assertTrue(Math.abs(parsedDate.getTime() - System.currentTimeMillis() + FIVE_MINUTES) < DELTA);

		String notOnOrAfter = samlConditions.getAttribute(SAMLAttributes.NOT_ON_OR_AFTER);
		assertEquals(isZuluTimeFormat, createdTime.getFirstChild().getNodeValue().endsWith("Z"));
		parsedDate = XmlUtil.fromXMLTimeStamp(notOnOrAfter);
		// NotBefore is set to five minutes before 'now'
		assertTrue(Math.abs(parsedDate.getTime() - System.currentTimeMillis() + FIVE_MINUTES - TWENTYFOUR_HOURS) < DELTA);
	}

	public void testMessage() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();

		Request request = factory.createNewRequest(false, null);
		Reply reply = factory.createNewReply(request, FlowStatusValues.FLOW_FINALIZED_SUCCESFULLY);
		assertEquals(DGWSConstants.VERSION_1_0_1, reply.getDGWSVersion());

		Document doc = reply.serialize2DOMDocument();
		Element createdTime = XmlUtil.selectSingleElement(doc, "//" + NameSpaces.NS_WSU + ":Created", new ModelPrefixResolver(), true);
		String xmlTimestamp = createdTime.getFirstChild().getNodeValue();
		// Remove 'Z'
		xmlTimestamp = xmlTimestamp.substring(0, xmlTimestamp.length() - 1);
		createdTime.getFirstChild().setNodeValue(xmlTimestamp);
		Reply deserializedReply = factory.deserializeReply(XmlUtil.node2String(doc));
		assertEquals(DGWSConstants.VERSION_1_0, deserializedReply.getDGWSVersion());
		assertFalse(reply.equals(deserializedReply));

		try {
			factory.createNewErrorReply("some version", "inResponseToID", "flowID", "faultCode", "faultString");
			fail("Should fail on invalid dgwsVersion");
		} catch (ModelException me) {
			// ok
		}

		try {
			factory.createNewErrorReply(null, "inResponseToID", "flowID", "faultCode", "faultString");
			fail("Should fail on empty dgwsVersion");
		} catch (ModelException me) {
			// ok
		}

		factory.createNewErrorReply(DGWSConstants.VERSION_1_0, "inResponseToID", "flowID", "faultCode", "faultString");
		factory.createNewErrorReply(DGWSConstants.VERSION_1_0_1, "inResponseToID", "flowID", "faultCode", "faultString");

	}

	public void testClient_1_0_Server_1_0() throws Exception {
		dgwsTest(DGWSConstants.VERSION_1_0, DGWSConstants.VERSION_1_0);
	}

	public void testClient_1_0_1_Server_1_0_1() throws Exception {
		dgwsTest(DGWSConstants.VERSION_1_0_1, DGWSConstants.VERSION_1_0_1);
	}

	public void testClient_1_0_Server_1_0_1() throws Exception {
		dgwsTest(DGWSConstants.VERSION_1_0, DGWSConstants.VERSION_1_0_1);
	}

	public void testClient_1_0_1_Server_1_0() throws Exception {
		dgwsTest(DGWSConstants.VERSION_1_0_1, DGWSConstants.VERSION_1_0);
	}

	private void dgwsTest(String clientVersion, String serverVersion) {
		Properties clientProperties = new Properties();
		clientProperties.put(SOSIFactory.PROPERTYNAME_SOSI_DGWS_VERSION, clientVersion);
		SOSIFactory clientFactory = new SOSIFactory(new EmptyCredentialVault(), clientProperties);

		Properties serverProperties = new Properties();
		serverProperties.put(SOSIFactory.PROPERTYNAME_SOSI_DGWS_VERSION, serverVersion);
		SOSIFactory serverFactory = new SOSIFactory(new EmptyCredentialVault(), serverProperties);

		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "12345", "someOrg");
		IDCard idCard = clientFactory.createNewSystemIDCard("itSystem", careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);

		// SecurityToken roundtrip
		SecurityTokenRequest tokenRequest = clientFactory.createNewSecurityTokenRequest();
		assertEquals(clientVersion, tokenRequest.getDGWSVersion());
		tokenRequest.setIDCard(idCard);
		Document doc = tokenRequest.serialize2DOMDocument();
		SecurityTokenRequest deserializedTokenRequest = serverFactory.deserializeSecurityTokenRequest(XmlUtil.node2String(doc));
		assertEquals(tokenRequest.getDGWSVersion(), deserializedTokenRequest.getDGWSVersion());
		assertEquals(tokenRequest, deserializedTokenRequest);

		SecurityTokenResponse tokenResponse = serverFactory.createNewSecurityTokenResponse(tokenRequest);
		assertEquals(clientVersion, tokenResponse.getDGWSVersion());
		tokenResponse.setIDCard(idCard);
		doc = tokenResponse.serialize2DOMDocument();
		SecurityTokenResponse deserializedTokenResponse = clientFactory.deserializeSecurityTokenResponse(XmlUtil.node2String(doc));
		assertEquals(tokenResponse.getDGWSVersion(), deserializedTokenResponse.getDGWSVersion());
		assertEquals(tokenResponse, deserializedTokenResponse);

		tokenResponse = serverFactory.createNewSecurityTokenErrorResponse(tokenRequest, "faultCode", "faultString", "faultActor");
		assertEquals(clientVersion, tokenResponse.getDGWSVersion());
		doc = tokenResponse.serialize2DOMDocument();
		deserializedTokenResponse = clientFactory.deserializeSecurityTokenResponse(XmlUtil.node2String(doc));
		assertEquals(tokenResponse.getDGWSVersion(), deserializedTokenResponse.getDGWSVersion());
		assertEquals(tokenResponse, deserializedTokenResponse);

		tokenResponse = serverFactory.createNewSecurityTokenErrorResponse(serverVersion, "inResponseToID", "faultCode", "faultString", "faultActor");
		assertEquals(serverVersion, tokenResponse.getDGWSVersion());
		doc = tokenResponse.serialize2DOMDocument();
		deserializedTokenResponse = serverFactory.deserializeSecurityTokenResponse(XmlUtil.node2String(doc));
		assertEquals(tokenResponse.getDGWSVersion(), deserializedTokenResponse.getDGWSVersion());
		assertEquals(tokenResponse, deserializedTokenResponse);

		// Request roundtrip
		Request request = clientFactory.createNewRequest(false, "flowID");
		assertEquals(clientVersion, request.getDGWSVersion());
		request.setIDCard(idCard);
		doc = request.serialize2DOMDocument();
		Request deserializedRequest = serverFactory.deserializeRequest(XmlUtil.node2String(doc));
		assertEquals(request.getDGWSVersion(), deserializedRequest.getDGWSVersion());
		assertEquals(request, deserializedRequest);

		Element headerNode = null;
		if (!System.getProperty("java.specification.version").equals("1.4")) {
			// disabled on jdk 1.4 due to insufficient handling of namespaces in
			// the version of Xalan shipped with the jdk
			headerNode = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
			RequestHeader requestHeader = serverFactory.deserializeRequestHeader(XmlUtil.node2String(headerNode));
			assertEquals(request.getDGWSVersion(), requestHeader.getDGWSVersion());
		}

		Reply reply = serverFactory.createNewReply(request, FlowStatusValues.FLOW_RUNNING);
		assertEquals(clientVersion, reply.getDGWSVersion());
		reply.setIDCard(idCard);
		doc = reply.serialize2DOMDocument();
		Reply deserializedReply = clientFactory.deserializeReply(XmlUtil.node2String(doc));
		assertEquals(reply.getDGWSVersion(), deserializedReply.getDGWSVersion());
		assertEquals(reply, deserializedReply);

		if (!System.getProperty("java.specification.version").equals("1.4")) {
			// disabled on jdk 1.4 due to insufficient handling of namespaces in
			// the version of Xalan shipped with the jdk
			headerNode = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Header").item(0);
			ReplyHeader replyHeader = clientFactory.deserializeReplyHeader(XmlUtil.node2String(headerNode));
			assertEquals(request.getDGWSVersion(), replyHeader.getDGWSVersion());
		}

		reply = serverFactory.createNewErrorReply(request, "faultCode", "faultString");
		assertEquals(clientVersion, reply.getDGWSVersion());
		doc = reply.serialize2DOMDocument();
		deserializedReply = serverFactory.deserializeReply(XmlUtil.node2String(doc));
		assertEquals(reply.getDGWSVersion(), deserializedReply.getDGWSVersion());
		assertEquals(reply, deserializedReply);

		reply = serverFactory.createNewErrorReply(serverVersion, "inResponseToID", "flowID", "faultCode", "faultString");
		assertEquals(serverVersion, reply.getDGWSVersion());
		doc = reply.serialize2DOMDocument();
		deserializedReply = serverFactory.deserializeReply(XmlUtil.node2String(doc));
		assertEquals(reply.getDGWSVersion(), deserializedReply.getDGWSVersion());
		assertEquals(reply, deserializedReply);
	}

	public void testSignatureInvalidException_1_0() throws Exception {
		String version = DGWSConstants.VERSION_1_0;
		signatureInvalidExceptionTest(version);
	}

	public void testSignatureInvalidException_1_0_1() throws Exception {
		String version = DGWSConstants.VERSION_1_0_1;
		signatureInvalidExceptionTest(version);
	}

	private void signatureInvalidExceptionTest(String version) {
		Properties properties = new Properties();
		properties.put(SOSIFactory.PROPERTYNAME_SOSI_DGWS_VERSION, version);
		SOSIFactory factory = new SOSIFactory(new EmptyCredentialVault(), properties);

		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "12345", "someOrg");
		UserInfo userInfo = new UserInfo("cpr", "givenName", "surName", "email", "occupation", "role", "authorizationCode");
		IDCard idCard = factory.createNewUserIDCard("itSystemName", userInfo, careProvider, AuthenticationLevel.MOCES_TRUSTED_USER, null, null, null, null);

		SecurityTokenRequest tokenRequest = factory.createNewSecurityTokenRequest();
		tokenRequest.setIDCard(idCard);

		Document doc = tokenRequest.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc, false, true);

		try {
			factory.deserializeSecurityTokenRequest(xml);
			fail("Deserializing an ID card with no signature should result in an exception");
		} catch (SignatureInvalidModelBuildException simbe) {
			assertEquals(version, simbe.getDGWSVersion());
		}

		Request request = factory.createNewRequest(false, FlowStatusValues.FLOW_RUNNING);
		request.setIDCard(idCard);

		doc = request.serialize2DOMDocument();
		xml = XmlUtil.node2String(doc, false, true);

		try {
			factory.deserializeRequest(xml);
			fail("Deserializing an ID card with no signature should result in an exception");
		} catch (SignatureInvalidModelBuildException simbe) {
			assertEquals(version, simbe.getDGWSVersion());
		}
	}

}
