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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/TestSOSIFactory.java $
 * $Id: TestSOSIFactory.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.model.dombuilders.SAMLUtil;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.modelbuilders.ModelPrefixResolver;
import dk.sosi.seal.pki.*;
import dk.sosi.seal.pki.testobjects.CredentialVaultAdapter;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.util.Properties;

/**
 * Test SOSIFactory
 *
 * @author kkj
 * @version 1.0 Apr 28, 2006
 * @since 1.0
 */
public class TestSOSIFactory extends TestCase {

	public void testSOSIFactoryConstruction() throws Exception {
		try {
			new SOSIFactory(null, System.getProperties());
			fail("Constructor should fail with credentialvault='null'");
		} catch (ModelException re) {
			// OK!
		}
		try {
			new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), null);
			fail("Constructor should fail with properties='null'");
		} catch (ModelException re) {
			// OK!
		}
	}

	public void testCreateRequest() throws Exception {

		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());
		assertEquals(System.getProperties(), factory.getProperties());

		String flowID = null;
		String issuer = "testissuer";
		System.getProperties().setProperty("issuer", issuer);
		boolean nonRep = false;

		Request req = factory.createNewRequest(nonRep, flowID);
		checkRequest(req, nonRep, flowID);

		flowID = "1234";
		nonRep = true;
		req = factory.createNewRequest(nonRep, flowID);
		checkRequest(req, nonRep, flowID);

		try {
			req.serialize2DOMDocument();
			fail("Should fail with req.idcard='null'");
		} catch (ModelException me) {
			// OK!
		}

		assertEquals(req, req); // Check equals()
		Request req1 = factory.createNewRequest(nonRep, flowID);
		assertFalse(req.equals(req1)); // Different messageID's
		assertFalse(req.getMessageID().equals(req1.getMessageID()));

		CareProvider careProvider = createCareProvider();

		req.setIDCard(createVOCESSignedSystemIDCard(factory, careProvider, null));
		Document doc = req.serialize2DOMDocument();
		assertTrue(doc.getDocumentElement().getChildNodes().getLength() > 0);

	}

	public void testIDCard() {

		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());

		String issuer = "testissuer";
		System.getProperties().setProperty("sosi:issuer", issuer);

		String flowID = "1234";
		boolean nonRep = true;
		Request req = factory.createNewRequest(nonRep, flowID);

		CareProvider careProvider = createCareProvider();

		// test systemidcard with voces
		IDCard idCard = createVOCESSignedSystemIDCard(factory,careProvider, null);
		assertTrue(idCard.getIssuer().equals("testissuer"));
		Element idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		String xml = XmlUtil.node2String(idCardElement, true, true);
		IDCard deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard, deserializedIDCard);
		req.setIDCard(idCard);
		req.serialize2DOMDocument(XmlUtil.createEmptyDocument());


		// test systemidcard with no authentification
		idCard = factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
		assertTrue(idCard.getIssuer().equals("testissuer"));
		idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(idCardElement, false, true);
		deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard, deserializedIDCard);
		req.setIDCard(idCard);
		req.serialize2DOMDocument(XmlUtil.createEmptyDocument());

		// test useridcard with moces
		UserInfo userInfo = new UserInfo("2601610143", "Peter", "Buus", "peter@signaturgruppen.dk", "hacker", "nurse", "2101");
		idCard = factory.createNewUserIDCard("SOSITEST", userInfo, createCareProvider(), AuthenticationLevel.MOCES_TRUSTED_USER, null, null,
				factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
		idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(idCardElement, false, true);
		deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard, deserializedIDCard);
		req.setIDCard(idCard);
		req.serialize2DOMDocument(XmlUtil.createEmptyDocument());
		// TODO: Assertions?

		// test useridcard with no authentification
		idCard = factory.createNewUserIDCard("SOSITEST", userInfo, createCareProvider(), AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
		idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(idCardElement, false, true);
		deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard, deserializedIDCard);
		req.setIDCard(idCard);
		req.serialize2DOMDocument(XmlUtil.createEmptyDocument());
		// TODO: Assertions?
	}

	public void testInvalidIDCards() throws Exception {
		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());
		CareProvider careProvider = createCareProvider();

		UserInfo userInfo = new UserInfo("9999999999", "John", "Doe", "spam@somesite.dk", "hacker", "doctor", "2101");
		IDCard idCard = factory.createNewUserIDCard("SOSITEST", userInfo, careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null,
				factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
		Document doc = XmlUtil.createEmptyDocument();

		// Create a DOM document with the serialized UserIDCard
		Request req = factory.createNewRequest(false, "1234");
		req.setIDCard(idCard);
		doc = XmlUtil.createEmptyDocument();
		req.serialize2DOMDocument(doc);
		Document validDocument = doc;

		// Fetch the IDCardType element
		doc = (Document)validDocument.cloneNode(true);
		Element samlAttrIDCardType = getIDCardTypeAttributeValueElement(doc);

		// Replace the value with an invalid type designation
		samlAttrIDCardType.replaceChild(doc.createTextNode("bogus"),samlAttrIDCardType.getFirstChild());

		// Check that the DOM serializer fails when building the model
		try {
			req = factory.deserializeRequest(XmlUtil.node2String(doc,false,false));
			fail("Modelbuilder does not fail on invalid id card type!");
		} catch (ModelBuildException mbe) {
			// OK!
		}

		// Replace the value with 'system'. System IDCards should not have UserLog entries.
		doc = (Document)validDocument.cloneNode(true);
		samlAttrIDCardType = getIDCardTypeAttributeValueElement(doc);
		samlAttrIDCardType.replaceChild(doc.createTextNode(IDCard.IDCARDTYPE_SYSTEM),samlAttrIDCardType.getFirstChild());
		// Check that the DOM serializer fails when building the model
		try {
			req = factory.deserializeRequest(XmlUtil.node2String(doc,false,false));
			fail("Modelbuilder should fail when SystemIDCards has UserLog elements!");
		} catch (ModelBuildException mbe) {
			// OK!
		}

		// Remove IDCard data element.
		checkMissingAttrStmt(factory, validDocument, IDValues.IDCARD_DATA, "Modelbuilder should fail when IDCardData element is missing");
		checkMissingAttrStmt(factory, validDocument, IDValues.SYSTEM_LOG, "Modelbuilder should fail when SystemLog element is missing");
		checkMissingAttrStmt(factory, validDocument, IDValues.USER_LOG, "Modelbuilder should fail when UserLog element is missing in UserIDCards");
	}

	public void testAlternativeIdentifiersForIDCards() throws Exception {

		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());

		CareProvider careProvider = createCareProvider();

		String alternativeIdentifier = "someAlternativeIdentifier";

		// test systemidcard with voces
		IDCard idCard = createVOCESSignedSystemIDCard(factory,careProvider, alternativeIdentifier);
		assertEquals(alternativeIdentifier, idCard.getAlternativeIdentifier());
		Element idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		String xml = XmlUtil.node2String(idCardElement, false, true);
		IDCard deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard.getAlternativeIdentifier(), deserializedIDCard.getAlternativeIdentifier());
		assertEquals(idCard, deserializedIDCard);


		// test systemidcard with no authentification
		idCard = factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, alternativeIdentifier);
		assertEquals(alternativeIdentifier, idCard.getAlternativeIdentifier());
		idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(idCardElement, false, true);
		deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard.getAlternativeIdentifier(), deserializedIDCard.getAlternativeIdentifier());
		assertEquals(idCard, deserializedIDCard);

		// test useridcard with moces
		UserInfo userInfo = new UserInfo("2601610143", "Peter", "Buus", "peter@signaturgruppen.dk", "hacker", "nurse", "2101");
		idCard = factory.createNewUserIDCard("SOSITEST", userInfo, createCareProvider(), AuthenticationLevel.MOCES_TRUSTED_USER,
				null, null, factory.getCredentialVault().getSystemCredentialPair().getCertificate(), alternativeIdentifier);
		assertEquals(alternativeIdentifier, idCard.getAlternativeIdentifier());
		idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(idCardElement, false, true);
		deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard.getAlternativeIdentifier(), deserializedIDCard.getAlternativeIdentifier());
		assertEquals(idCard, deserializedIDCard);

		// test useridcard with no authentification
		idCard = factory.createNewUserIDCard("SOSITEST", userInfo, createCareProvider(), AuthenticationLevel.NO_AUTHENTICATION, null, null, null, alternativeIdentifier);
		assertEquals(alternativeIdentifier, idCard.getAlternativeIdentifier());
		idCardElement = idCard.serialize2DOMDocument(factory, XmlUtil.createEmptyDocument());
		xml = XmlUtil.node2String(idCardElement, false, true);
		deserializedIDCard = factory.deserializeIDCard(xml);
		assertEquals(idCard.getAlternativeIdentifier(), deserializedIDCard.getAlternativeIdentifier());
		assertEquals(idCard, deserializedIDCard);
	}

	/**
	 *  Test the combination of careproviders and generation of SAML Subject name ID
	 * @throws TransformerException
	 */
	public void testCareProvidersInSystemIDCards() throws Exception {
		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());

		checkCareProviderAndSubjectNameID(factory, SubjectIdentifierTypeValues.CVR_NUMBER);
		checkCareProviderAndSubjectNameID(factory, SubjectIdentifierTypeValues.Y_NUMBER);
		checkCareProviderAndSubjectNameID(factory, SubjectIdentifierTypeValues.P_NUMBER);
		checkCareProviderAndSubjectNameID(factory, SubjectIdentifierTypeValues.SKS_CODE);

	}

	public void testSecurityTokenRequest() {

		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());
		String issuer = "testissuer";
		System.getProperties().setProperty("sosi:issuer", issuer);

		SecurityTokenRequest securityTokenRequest = factory.createNewSecurityTokenRequest();

		try {
			securityTokenRequest.serialize2DOMDocument();
			fail("Must fail with no ID Card present");
		} catch (ModelException e) {
			// OK
		}

		try {
			securityTokenRequest.setFlowID("NOT APPLICABLE");
			fail("Flow ID not applicable for SecurityTokenRequest");
		} catch (ModelException e) {
			// OK
		}

		CareProvider careProvider = createCareProvider();
		IDCard idCard = createVOCESSignedSystemIDCard(factory,careProvider, null);
		securityTokenRequest.setIDCard(idCard);

		Document doc = securityTokenRequest.serialize2DOMDocument();

		Node signature = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature").item(0);
		assertNotNull(signature);
		assertTrue(SignatureUtil.validate(signature, factory.getFederation(),factory.getCredentialVault(),true));

		try {
			String xml = XmlUtil.node2String(doc, false, true);
			SecurityTokenRequest securityTokenRequest1 = factory.deserializeSecurityTokenRequest(xml);
			assertTrue(securityTokenRequest.equals(securityTokenRequest1));
			assertEquals(securityTokenRequest.hashCode(), securityTokenRequest1.hashCode());
			Document doc1 = securityTokenRequest1.serialize2DOMDocument();
            assertTrue(XmlUtil.deepDiff(doc, doc1) == null);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error parsing SecurityTokenRequest "+e.getMessage());
		}

	}

	public void testSecurityTokenRequestWithEmptyCredentialVaultAndWithNoAuthSystemID() {

		SOSIFactory factory = new SOSIFactory(new EmptyCredentialVault(), System.getProperties());
		String issuer = "testissuer";
		System.getProperties().setProperty("sosi:issuer", issuer);

		SecurityTokenRequest securityTokenRequest = factory.createNewSecurityTokenRequest();

		try {
			securityTokenRequest.serialize2DOMDocument();
			fail("Must fail with no ID Card present");
		} catch (Exception e) {
			// OK
		}

		try {
			securityTokenRequest.setFlowID("NOT APPLICABLE");
			fail("Flow ID not applicable for SecurityTokenRequest");
		} catch (Exception e) {
			// OK
		}

		CareProvider careProvider = createCareProvider();
		IDCard idCard = factory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
		securityTokenRequest.setIDCard(idCard);

		Document doc = securityTokenRequest.serialize2DOMDocument();

		Node signature = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature").item(0);
		assertNull(signature);

		try {
			String xml = XmlUtil.node2String(doc, false, true);
			SecurityTokenRequest securityTokenRequest1 = factory.deserializeSecurityTokenRequest(xml);
			assertTrue(securityTokenRequest.equals(securityTokenRequest1));
			assertEquals(securityTokenRequest.hashCode(), securityTokenRequest1.hashCode());
			Document doc1 = securityTokenRequest1.serialize2DOMDocument();
			XmlUtil.node2String(doc1, false, true);
			assertTrue(XmlUtil.deepDiff(doc, doc1) == null);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error parsing SecurityTokenRequest");
		}

	}

	public void testSecurityTokenResponse() {

		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());
		String issuer = "testissuer";
		System.getProperties().setProperty("sosi:issuer", issuer);
		SecurityTokenRequest request = factory.createNewSecurityTokenRequest();

		SecurityTokenResponse securityTokenResponse = factory.createNewSecurityTokenErrorResponse(request, "FAILURE", "ERROR", "ACTOR");
		assertEquals("FAILURE", securityTokenResponse.getFaultCode());
		assertEquals("ERROR", securityTokenResponse.getFaultString());
		Document errorResponseDoc = XmlUtil.createEmptyDocument();
		securityTokenResponse.serialize2DOMDocument(errorResponseDoc);

		try {
			String xml = XmlUtil.node2String(errorResponseDoc, false, true);
			SecurityTokenResponse securityTokenResponse1 = factory.deserializeSecurityTokenResponse(xml);
			assertTrue(securityTokenResponse.equals(securityTokenResponse1));
			Document doc1 = XmlUtil.createEmptyDocument();
			securityTokenResponse1.serialize2DOMDocument(doc1);
			assertTrue(XmlUtil.deepDiff(errorResponseDoc, doc1) == null);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error parsing SecurityTokenResponse with error");
		}

		SecurityTokenRequest newRequest = factory.createNewSecurityTokenRequest();
		SecurityTokenResponse securityTokenResponseError = factory.createNewSecurityTokenErrorResponse(newRequest, "FAILURE", "ERROR", "ACTOR");
		// on slow computers createdate can be different
		securityTokenResponseError.setCreationDate(securityTokenResponse.getCreationDate());

		assertFalse(securityTokenResponse.equals(securityTokenResponseError));
		securityTokenResponseError.setMessageID(securityTokenResponse.getMessageID());
		assertTrue(securityTokenResponse.equals(securityTokenResponseError));

		securityTokenResponseError = factory.createNewSecurityTokenErrorResponse(request, "FUILARE", "ERROR", "ACTOR");
		assertFalse(securityTokenResponse.equals(securityTokenResponseError));
		securityTokenResponseError.setMessageID(securityTokenResponse.getMessageID());
		assertFalse(securityTokenResponse.equals(securityTokenResponseError));

		securityTokenResponseError = factory.createNewSecurityTokenErrorResponse(request, "FAILURE", "ORRER", "ACTOR");
		assertFalse(securityTokenResponse.equals(securityTokenResponseError));
		securityTokenResponseError.setMessageID(securityTokenResponse.getMessageID());
		assertFalse(securityTokenResponse.equals(securityTokenResponseError));

		securityTokenResponse = factory.createNewSecurityTokenResponse(newRequest);

		try {
			securityTokenResponse.serialize2DOMDocument(XmlUtil.createEmptyDocument());
			fail("Must fail with no ID Card present");
		} catch (ModelException e) {
			// OK
		}

		try {
			securityTokenResponse.setFlowID("NOT APPLICABLE");
			fail("Flow ID not applicable for SecurityTokenResponse");
		} catch (Exception e) {
			// OK
		}

		try {
			securityTokenResponse.getFaultCode();
			fail("getFaultCode should fail for errorless SecurityTokenResponse");
		} catch (Exception e) {
			// OK
		}

		try {
			securityTokenResponse.getFaultString();
			fail("getFaultString should fail for errorless SecurityTokenResponse");
		} catch (Exception e) {
			// OK
		}

		CareProvider careProvider = createCareProvider();
		IDCard idCard =createVOCESSignedSystemIDCard(factory,careProvider, null);
		securityTokenResponse.setIDCard(idCard);

		Document doc = XmlUtil.createEmptyDocument();
		securityTokenResponse.serialize2DOMDocument(doc);

		Node signature = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature").item(0);
		assertNotNull(signature);
		assertTrue(SignatureUtil.validate(signature, factory.getFederation(),factory.getCredentialVault(),true));

		try {
			String xml = XmlUtil.node2String(doc, false, true);
			SecurityTokenResponse securityTokenResponse1 = factory.deserializeSecurityTokenResponse(xml);
			assertTrue(securityTokenResponse.equals(securityTokenResponse1));
			Document doc1 = XmlUtil.createEmptyDocument();
			securityTokenResponse1.serialize2DOMDocument(doc1);
			assertTrue(XmlUtil.deepDiff(doc, doc1) == null);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error parsing SecurityTokenResponse");
		}

	}

	public void testSTSLoop() {

		SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), System.getProperties());
		String issuer = "testissuer";
		System.getProperties().setProperty("sosi:issuer", issuer);

		SecurityTokenRequest securityTokenRequest = factory.createNewSecurityTokenRequest();

		CareProvider careProvider = createCareProvider();
		IDCard idCardBeforeSerialization = createVOCESSignedSystemIDCard(factory,careProvider, null);
		securityTokenRequest.setIDCard(idCardBeforeSerialization);

		Document doc = XmlUtil.createEmptyDocument();
		securityTokenRequest.serialize2DOMDocument(doc);

		Node signature = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature").item(0);
		assertNotNull(signature);
		assertTrue(SignatureUtil.validate(signature, factory.getFederation(), factory.getCredentialVault(),true));

		SecurityTokenRequest afterSentOverTheWire = null;
		try {
			String xml = XmlUtil.node2String(doc, false, true);
			afterSentOverTheWire = factory.deserializeSecurityTokenRequest(xml);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error parsing SecurityTokenRequest");
		}

		SecurityTokenResponse securityTokenResponse = factory.createNewSecurityTokenResponse(afterSentOverTheWire);
		securityTokenResponse.setIDCard(factory.copyToVOCESSignedIDCard(afterSentOverTheWire.getIDCard()));
		Document responseDoc = XmlUtil.createEmptyDocument();
		securityTokenResponse.serialize2DOMDocument(responseDoc);
		Node responseSignature = responseDoc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, "Signature").item(0);
		assertTrue(SignatureUtil.validate(responseSignature, factory.getFederation(), factory.getCredentialVault(),true));

	}

	public void testFederationSetup() throws Exception {
		try {
            Properties properties = SignatureUtil.setupCryptoProviderForJVM();

			GenericCredentialVault vault = CredentialVaultTestUtil.getVocesCredentialVault(properties);

			SOSIFactory factory = new SOSIFactory(vault, properties);
			assertNull(factory.getFederation());

			SOSITestFederation testFederation = new SOSITestFederation(properties);
			factory = new SOSIFactory(testFederation, vault, properties);

			assertEquals(vault, factory.getCredentialVault());
			assertTrue(factory.getFederation() != null);
			assertTrue(factory.getFederation() instanceof SOSITestFederation);

            SOSIFederation federation = new SOSIFederation(properties, CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVault());
			factory = new SOSIFactory(federation, vault, properties);

			assertEquals(vault, factory.getCredentialVault());
			assertTrue(factory.getFederation() != null);
			assertTrue(factory.getFederation() instanceof SOSIFederation);

            try {
                federation.getCertificationAuthority().isValid(vault.getSystemCredentialPair().getCertificate());
                fail();
            } catch (PKIException e) {
               assertEquals("Intermediate certificate not issued by OCES Production root certificate", e.getMessage());
            }

		} catch (PKIException e) {
			System.out.println("May be offline! - test not run..");
			System.out.println(e.getMessage());
		}
	}

    public void testCreateNewSystemIDCard() throws IOException {
        String sysId = "mySYS";
        CareProvider cp = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "123456789", "myTestOrg");
        AuthenticationLevel authenticationLevel = AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION;
        String username = "username";
        String password = "password";
        String alternativeIdentifie = "altIdent";

        SystemIDCard sysIdCard = new SOSIFactory(new CredentialVaultAdapter(), new Properties()).createNewSystemIDCard(sysId, cp, authenticationLevel, username, password, null, alternativeIdentifie);

        assertEquals("alternativeIdentifier", "altIdent", sysIdCard.getAlternativeIdentifier());
        assertEquals("authenticationLevel", AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, sysIdCard.getAuthenticationLevel());
        assertEquals("password", "password", sysIdCard.getPassword());
        assertEquals("username", "username", sysIdCard.getUsername());
        assertSame("systemInfo.careProvider", cp, sysIdCard.getSystemInfo().getCareProvider());
        assertEquals("systemInfo.itSystemName", "mySYS", sysIdCard.getSystemInfo().getITSystemName());
    }

    public void testInstantiationWithCredentialVaultBasedSignatureProvider() {
        Properties properties = System.getProperties();
        CredentialVault vault = new EmptyCredentialVault();
        SignatureProvider signatureProvider = SignatureProviderFactory.fromCredentialVault(vault);
        Federation federation = new SOSIFederation(properties);
        SOSIFactory sosiFactory = new SOSIFactory(federation, signatureProvider, properties);
        assertEquals(vault, sosiFactory.getCredentialVault());
        assertEquals(signatureProvider, sosiFactory.getSignatureProvider());
        assertEquals(properties, sosiFactory.getProperties());
        assertEquals(federation, sosiFactory.getFederation());
    }

    public void testInstantiationWithNotCredentialVaultBasedSignatureProvider() {
        Properties properties = System.getProperties();
        SignatureProvider signatureProvider = new SignatureProvider() {
            public SignatureResult sign(byte[] bytes) throws PKIException {
                return null;
            }
        };
        Federation federation = new SOSIFederation(properties);
        SOSIFactory sosiFactory = new SOSIFactory(federation, signatureProvider, properties);
        assertNull(sosiFactory.getCredentialVault());
        assertFalse(sosiFactory.getSignatureProvider() instanceof CredentialVaultSignatureProvider);
        assertEquals(signatureProvider, sosiFactory.getSignatureProvider());
        assertEquals(properties, sosiFactory.getProperties());
        assertEquals(federation, sosiFactory.getFederation());
    }

    public void testSignWithNotCredentialVaultBasedSignatureProvider() {
        Properties properties = System.getProperties();
        SignatureProvider signatureProvider = new SignatureProvider() {
            public SignatureResult sign(byte[] bytes) throws PKIException {
                return SignatureProviderFactory.fromCredentialVault(CredentialVaultTestUtil.getCredentialVault()).sign(bytes);
            }
        };
        Federation federation = new SOSIFederation(properties);
        SOSIFactory sosiFactory = new SOSIFactory(federation, signatureProvider, properties);
        assertNull(sosiFactory.getCredentialVault());

        SecurityTokenRequest tokenRequest = sosiFactory.createNewSecurityTokenRequest();
        SystemIDCard idCard = createVOCESSignedSystemIDCard(sosiFactory, createCareProvider(), null);
        tokenRequest.setIDCard(idCard);

        //Side-effect: idCard gets signed
        tokenRequest.serialize2DOMDocument();

        idCard.validateSignatureAndTrust(CredentialVaultTestUtil.getCredentialVault());

        try {
            idCard.validateSignatureAndTrust(federation);
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

    }

    // ===========================
	//  Private parts
	// ===========================

	private void checkRequest(Request req, boolean nonRep, String flowID) {
		assertEquals(nonRep, req.isDemandNonRepudiationReceipt());
		assertEquals(flowID, req.getFlowID());
		assertNotNull(req.getCreationDate());
		assertNotNull(req.getCreationDate());
		assertTrue(req.getCreationDate().getTime() <= System.currentTimeMillis());
		assertNotNull(req.getMessageID());
	}

	private Element getIDCardTypeAttributeValueElement(Document doc) throws Exception {
		Element samlAttrIDCardType = new SAMLUtil().fetchSamlAttributeValue(doc,SOSIAttributes.IDCARD_TYPE);
		assertNotNull(samlAttrIDCardType);
		return samlAttrIDCardType;
	}

	private void checkMissingAttrStmt(SOSIFactory factory, Document validDocument, String stmtID, String failureMessage) throws Exception {
		Document doc  = (Document)validDocument.cloneNode(true);
		Element iattrStmt = new SAMLUtil().fetchSamlAttributeStatement(doc,stmtID);
		iattrStmt.getParentNode().removeChild(iattrStmt);
		// Check that the DOM serializer fails when building the model
		try {
			factory.deserializeRequest(XmlUtil.node2String(doc,false,false));
			fail(failureMessage);
		} catch (ModelBuildException mbe) {
			// OK!
		} catch (ModelException e) {
			// OK!
		}

	}

	private CareProvider createCareProvider() {
		return createCareProvider(SubjectIdentifierTypeValues.CVR_NUMBER);
	}

	private CareProvider createCareProvider(String type) {
		return new CareProvider(type, "someID", "someOrgName");
	}

	private SystemIDCard createVOCESSignedSystemIDCard(SOSIFactory factory, CareProvider careProvider, String alternativeIdentifier) {
		return factory.createNewSystemIDCard("SOSITEST", careProvider,AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, null, alternativeIdentifier);
	}

	private SystemIDCard createUnsignedSystemIDCard(SOSIFactory factory, CareProvider careProvider) {
		return factory.createNewSystemIDCard("SOSITEST", careProvider,AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
	}

	private void checkCareProviderAndSubjectNameID(SOSIFactory factory, String cpType) throws TransformerException {
		IDCard idCard = createUnsignedSystemIDCard(factory,createCareProvider(cpType));
		Document doc = XmlUtil.createEmptyDocument();
		Request req = factory.createNewRequest(false, "1234");
		req.setIDCard(idCard);
		req.serialize2DOMDocument(doc);
        Element subject = XmlUtil.selectSingleElement(doc, "//"+ SAMLTags.NAMEID_PREFIXED, new ModelPrefixResolver(), true);
		assertEquals(cpType,subject.getAttribute(SAMLAttributes.FORMAT));
	}
}
