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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/TestPerformance.java $
 * $Id: TestPerformance.java 34175 2017-05-30 17:38:04Z ChristianGasser $
 */
package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.FlowStatusValues;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.model.dombuilders.IDCardToOIOSAMLAssertionRequestDOMBuilder;
import dk.sosi.seal.model.dombuilders.IDCardToOIOSAMLAssertionResponseDOMBuilder;
import dk.sosi.seal.model.dombuilders.OIOSAMLAssertionToIDCardRequestDOMBuilder;
import dk.sosi.seal.model.dombuilders.OIOSAMLAssertionToIDCardResponseDOMBuilder;
import dk.sosi.seal.modelbuilders.IDCardToOIOSAMLAssertionRequestModelBuilder;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.util.SOSITestUtils;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Testcase used solely for performance testing.<br />
 * The tests have been written to spend a minimal amount of time constructing input parameters and validating the response.
 * 
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @version 1.0 Jun 16, 2006
 * @since 1.0
 */
public class TestPerformance extends TestCase {

    private static final int ITERATIONS = Integer.getInteger("dk.sosi.seal.responsetimedivider", 1).intValue();
    
    private SOSIFactory sosiFactory;
    private IDCard systemIDCard;
    private UserIDCard userIDCard;
    private String sosiReply;
    private String sosiRequest;
    private OIOSAMLFactory oiosamlFactory;
    private CredentialVault vault;
    private CredentialVault idPTrustVault;
    private Federation mockFederation;


    public void setUp() {
        vault = CredentialVaultTestUtil.getCredentialVault();
        idPTrustVault = SOSITestUtils.getNewestIdPTrustVault();
        sosiFactory = new SOSIFactory(vault, SignatureUtil.setupCryptoProviderForJVM());
        // Create a request and store it
        Request request = sosiFactory.createNewRequest(false, "1234abcdef");
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
        systemIDCard = sosiFactory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, vault.getSystemCredentialPair().getCertificate(), null);
        request.setIDCard(systemIDCard);
        Document doc = request.serialize2DOMDocument();
        sosiRequest = XmlUtil.node2String(doc, false, false);

        // Create a reply a and store it
        Reply reply = sosiFactory.createNewReply(request, FlowStatusValues.FLOW_FINALIZED_SUCCESFULLY);
        doc = reply.serialize2DOMDocument();
        sosiReply = XmlUtil.node2String(doc, false, false);

        oiosamlFactory = new OIOSAMLFactory();
        mockFederation = new SOSITestFederation(System.getProperties()) {
            @Override
            public boolean isValidSTSCertificate(X509Certificate certificate) {
                return vault.getSystemCredentialPair().getCertificate().equals(certificate);
            }
        };

        UserInfo userInfo = new UserInfo("1111111118", "Sepp", "Zwackelmann", "sepp@zwackelmann.dk", "mekaniker", "tester", null);
        userIDCard = sosiFactory.createNewUserIDCard("SOSITEST", userInfo, careProvider, AuthenticationLevel.MOCES_TRUSTED_USER, null, null, vault.getSystemCredentialPair().getCertificate(), null);
        userIDCard.serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument());
        userIDCard = (UserIDCard) sosiFactory.copyToVOCESSignedIDCard(userIDCard); // signs idCard
        userIDCard = (UserIDCard) sosiFactory.copyToVOCESSignedIDCard(userIDCard, true); // ensures idCard with correct Subject NameID
    }

    /**
     * Create a new System IDCard
     */
    public void testCreateNewSystemIDCard() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                IDCard card = sosiFactory.createNewSystemIDCard("SOSITEST", new CareProvider(SubjectIdentifierTypeValues.SKS_CODE, "1234", "sosi"), AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
                card.serialize2DOMDocument(null, XmlUtil.createEmptyDocument());
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to new system idcard");
        }
    }

    /**
     * Create a new User IDCard
     */
    public void testCreateNewUserIDCard() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                UserInfo userInfo = new UserInfo("0123456789", "perf", "ormance", "per@ormance.dk", "performer", "doctor", "123546");
                IDCard card = sosiFactory.createNewUserIDCard("www.sosi.dk/system", userInfo, new CareProvider(SubjectIdentifierTypeValues.P_NUMBER, "p1234", "performance.dk"), AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
                card.serialize2DOMDocument(null, XmlUtil.createEmptyDocument());
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create new user idcard");
        }
    }

    /**
     * Create a new reply. The net result is a complete SOAP message, ready for transmission
     */
    public void testCreateReply() {
        Request request = sosiFactory.createNewRequest(false, "wewewe");
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                Reply reply = sosiFactory.createNewReply(request, FlowStatusValues.FLOW_FINALIZED_SUCCESFULLY);
                reply.serialize2DOMDocument();
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create reply");
        }
    }

    /**
     * Create a new request, and install a new IDCard into it. The net result is a complete SOAP message, ready for transmission.
     */
    public void testCreateRequest() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                Request request = sosiFactory.createNewRequest(false, "1234abcdef");
                CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
                request.setIDCard(sosiFactory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
                request.serialize2DOMDocument();
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create request");
        }
    }

    /**
     * Create a new SecurityTokenRequest, and install a new IDCard into it. The net result is a complete SOAP message, ready for transmission.
     */
    public void testCreateSecurityTokenRequest() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                SecurityTokenRequest request = sosiFactory.createNewSecurityTokenRequest();
                CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
                request.setIDCard(sosiFactory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
                request.serialize2DOMDocument();
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create SecurityTokenRequest");
        }
    }

    /**
     * Create a new SecurityTokenResponse, and install a new IDCard into it. The net result is a complete SOAP message, ready for transmission.
     */
    public void testCreateSecurityTokenResponse() {
        try {
            SecurityTokenRequest request = sosiFactory.createNewSecurityTokenRequest();
            for (int i = 0; i < ITERATIONS; i++) {
                SecurityTokenResponse reply = sosiFactory.createNewSecurityTokenResponse(request);
                CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "orgCVR", "orgName");
                reply.setIDCard(sosiFactory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate(), null));
                reply.serialize2DOMDocument();
                // Logger.getLogger(getClass().getName()).info(XmlUtil.node2String(doc,false,true));
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create SecurityTokenRequest");
        }
    }

    /**
     * Deserialize an XML SOAP Reply into objects
     */
    public void testDeserializeReply() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                sosiFactory.deserializeReply(sosiReply);
            }
        } catch (ModelBuildException e) {
            e.printStackTrace();
            fail("Couldn't deserialize reply");
        }
    }

    /**
     * Deserialize an XML SOAP Request into objects
     */
    public void testDeserializeRequest() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                sosiFactory.deserializeRequest(sosiRequest);
            }
        } catch (ModelBuildException e) {
            e.printStackTrace();
            fail("Couldn't deserialize request");
        }
    }

    /**
     * Binary serialize and deserialize an IDCard
     */
    public void testIDCardBinarySerialization() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                ByteArrayOutputStream bas = new ByteArrayOutputStream();
                ObjectOutputStream ous = new ObjectOutputStream(new BufferedOutputStream(bas));
                ous.writeObject(systemIDCard);
                ous.flush();
                byte[] array = bas.toByteArray();
                ous.close();
                ByteArrayInputStream bais = new ByteArrayInputStream(array);
                ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(bais));
                ois.readObject();
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Couldn't perform binary serialization");
        }
    }

    /**
     * XML serialize and deserialize an IDCard
     */
    public void testIDCardXMLSerialization() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                Element idCardElement = systemIDCard.serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument());
                String xml = XmlUtil.node2String(idCardElement, false, true);
                sosiFactory.deserializeIDCard(xml);
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Couldn't perform xml serialization");
        }
    }

    /**
     * Measure round trip for OIOSAMLToIDCard issuance, that is
     *  - parse OIOSAMLAssertion
     *  - build STS request and serialize to DOM
     *  - parse request DOM and validate
     *  - build STS response and serialize
     *  - parse response DOM and validate
     */
    public void testOIOSAMLAssertionToSOSIIDCardRoundTrip() {

        try {
            for (int i = 0; i < ITERATIONS; i++) {
                OIOSAMLAssertion oiosamlAssertion = parseOIOSAMLAssertion();
                Document requestDoc = buildOIOSAMLToIDCardRequest(oiosamlAssertion);
                OIOSAMLAssertion assertion = parseAndValidateOIOSAMLToIDCardRequest(requestDoc);
                validateOIOSAMLAssertion(assertion);
                Document responseDoc = buildOIOSAMLToIDCardResponse();
                parseAndValidateOIOSAMLToIDCardResponse(responseDoc);
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Couldn't perform OIOSAMLAssertionToSOSIIDCardRoundTrip test");
        }
    }

    private void parseAndValidateOIOSAMLToIDCardResponse(Document responseDoc) {
        OIOSAMLAssertionToIDCardResponse assertionToIDCardResponse = oiosamlFactory.createOIOSAMLAssertionToIDCardResponseModelBuilder().build(responseDoc);
        assertEquals("1234", assertionToIDCardResponse.getRelatesTo());
        assertEquals("2345", assertionToIDCardResponse.getContext());
        assertEquals(systemIDCard, assertionToIDCardResponse.getIDCard());
        assertEquals("http://sosi.dk", assertionToIDCardResponse.getAppliesTo());
        assertEquals(vault.getSystemCredentialPair().getCertificate(), assertionToIDCardResponse.getSigningCertificate());

        assertionToIDCardResponse.validateSignature();
        assertionToIDCardResponse.validateSignatureAndTrust(mockFederation);
    }

    private Document buildOIOSAMLToIDCardResponse() {
        OIOSAMLAssertionToIDCardResponseDOMBuilder domBuilder = oiosamlFactory.createOIOSAMLAssertionToIDCardResponseDOMBuilder();
        domBuilder.setSigningVault(vault);
        domBuilder.setRelatesTo("1234");
        domBuilder.setContext("2345");
        domBuilder.setIDCard(systemIDCard);
        return domBuilder.build();
    }

    private void validateOIOSAMLAssertion(OIOSAMLAssertion assertion) {
        assertEquals("25450442", assertion.getCvrNumberIdentifier());
        assertEquals("_020a271f-be04-4378-84ce-0a3ccae065c1", assertion.getID());
        assertion.validateSignatureAndTrust(idPTrustVault);
    }

    private OIOSAMLAssertion parseAndValidateOIOSAMLToIDCardRequest(Document requestDoc) {
        OIOSAMLAssertionToIDCardRequest assertionToIDCardRequest = oiosamlFactory.createOIOSAMLAssertionToIDCardRequestModelBuilder().build(requestDoc);
        assertEquals("EMS", assertionToIDCardRequest.getITSystemName());
        assertEquals("2345C", assertionToIDCardRequest.getUserAuthorizationCode());
        assertEquals("7170", assertionToIDCardRequest.getUserEducationCode());
        assertEquals("Fritz", assertionToIDCardRequest.getUserGivenName());
        assertEquals("Müller", assertionToIDCardRequest.getUserSurName());
        assertEquals("http://sosi.dk", assertionToIDCardRequest.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", assertionToIDCardRequest.getAction());
        assertionToIDCardRequest.validateSignatureAndTrust(vault);
        assertEquals(vault.getSystemCredentialPair().getCertificate(), assertionToIDCardRequest.getSigningCertificate());

        return assertionToIDCardRequest.getOIOSAMLAssertion();
    }

    private Document buildOIOSAMLToIDCardRequest(OIOSAMLAssertion oiosamlAssertion) {
        OIOSAMLAssertionToIDCardRequestDOMBuilder domBuilder = oiosamlFactory.createOIOSAMLAssertionToIDCardRequestDOMBuilder();
        domBuilder.setSigningVault(vault);
        domBuilder.setOIOSAMLAssertion(oiosamlAssertion);
        domBuilder.setITSystemName("EMS");
        domBuilder.setUserAuthorizationCode("2345C");
        domBuilder.setUserEducationCode("7170");
        domBuilder.setUserGivenName("Fritz");
        domBuilder.setUserSurName("Müller");
        return domBuilder.build();
    }

    private OIOSAMLAssertion parseOIOSAMLAssertion() {
        String xml = SOSITestUtils.readXMLStreamAndRemoveFormatting(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-2.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), xml, false);
        return new OIOSAMLAssertion(document.getDocumentElement());
    }

    /**
     * Measure round trip for IDCardToOIOSAML issuance, that is
     *  - build STS request and serialize to DOM
     *  - parse request DOM and validate
     *  - build STS response, encrypt and serialize
     *  - parse response DOM and validate
     */
    public void testSOSIIDCardToOIOSAMLAssertionRoundTrip() {
        try {
            for (int i = 0; i < ITERATIONS; i++) {
                Document requestDoc = buildIDCardToOIOSAMLRequest();
                UserIDCard idCard = parseAndValidateIDCardToOIOSAMLRequest(requestDoc);
                Document responseDoc = buildIDCardToOIOSAMLResponse(createOIOSAMLAssertion(idCard));
                OIOSAMLAssertion oiosamlAssertion = parseAndValidateIDCardToOIOSAMLResponse(responseDoc);
                assertOIOSAMLAssertion(oiosamlAssertion, idCard);
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Couldn't perform SOSIIDCardToOIOSAMLAssertionRoundTrip test");
        }

    }

    private UserIDCard parseAndValidateIDCardToOIOSAMLRequest(Document requestDoc) {
        IDCardToOIOSAMLAssertionRequestModelBuilder builder = oiosamlFactory.createIDCardToOIOSAMLAssertionRequestModelBuilder();
        IDCardToOIOSAMLAssertionRequest request = builder.build(requestDoc);
        assertEquals("Sundhed.dk", request.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", request.getAction());
        request.validateSignature();
        request.validateSignatureAndTrust(vault);
        assertEquals(vault.getSystemCredentialPair().getCertificate(), request.getSigningCertificate());

        assertEquals(userIDCard, request.getUserIDCard());
        request.getUserIDCard().validateSignature();
        request.getUserIDCard().validateSignatureAndTrust(vault);
        return request.getUserIDCard();
    }

    private Document buildIDCardToOIOSAMLRequest() {
        IDCardToOIOSAMLAssertionRequestDOMBuilder builder = oiosamlFactory.createIDCardToOIOSAMLAssertionRequestDOMBuilder();
        builder.setSigningVault(vault);
        builder.setAudience("Sundhed.dk");
        builder.setUserIDCard(userIDCard);
        return builder.build();
    }

    private OIOSAMLAssertion createOIOSAMLAssertion(UserIDCard idCard) {
        OIOSAMLAssertionBuilder builder = oiosamlFactory.createOIOSAMLAssertionBuilder();
        builder.setSigningVault(vault);
        builder.setIssuer("Test STS");
        builder.setUserIdCard(idCard);
        Date now = new Date();
        builder.setNotBefore(now);
        builder.setNotOnOrAfter(new Date(now.getTime() + 60 * 60 * 1000));
        builder.setAudienceRestriction("http://sundhed.dk");
        builder.setRecipientURL("http://sundhed.dk/saml/SAMLAssertionConsumer");
        builder.setDeliveryNotOnOrAfter(new Date(now.getTime() + 5 * 60 * 1000));
        builder.includeIDCardAsBootstrapToken();
        return builder.build();
    }

    private Document buildIDCardToOIOSAMLResponse(OIOSAMLAssertion oiosamlAssertion) {
        IDCardToOIOSAMLAssertionResponseDOMBuilder builder = oiosamlFactory.createIDCardToOIOSAMLAssertionResponseDOMBuilder();
        builder.setSigningVault(vault);
        builder.setOIOSAMLAssertion(oiosamlAssertion);
        builder.setEncryptionKey(vault.getSystemCredentialPair().getCertificate().getPublicKey());
        builder.setRelatesTo("1234");
        builder.setContext("5678");
        return builder.build();
    }

    private OIOSAMLAssertion parseAndValidateIDCardToOIOSAMLResponse(Document responseDoc) {
        IDCardToOIOSAMLAssertionResponse response = oiosamlFactory.createIDCardToOIOSAMLAssertionResponseModelBuilder().build(responseDoc);

        assertEquals("http://sundhed.dk", response.getAppliesTo());
        response.validateSignature();
        response.validateSignatureAndTrust(mockFederation);

        Element decryptedAssertionElm = EncryptionUtil.decryptAndDetach(response.getEncryptedOIOSAMLAssertionElement(), vault.getSystemCredentialPair().getPrivateKey());
        return new OIOSAMLAssertion(decryptedAssertionElm);
    }


    private void assertOIOSAMLAssertion(OIOSAMLAssertion assertion, UserIDCard idCard) {
        assertEquals("42634739", assertion.getRidNumberIdentifier());
        assertEquals("C=DK,O=TRUST2408,CN=TRUST2408 Systemtest XIX CA", assertion.getCertificateIssuer());
        assertFalse(assertion.isYouthCertificate());
        assertEquals("5818c1a6", assertion.getCertificateSerial());
        assertEquals("CVR:30808460-RID:42634739", assertion.getUID());
        assertNotNull(assertion.getDeliveryNotOnOrAfter());
        assertTrue(assertion.getDeliveryNotOnOrAfter() instanceof Date);
        assertEquals("http://sundhed.dk/saml/SAMLAssertionConsumer", assertion.getRecipient());
        assertEquals(idCard, assertion.getUserIDCard());
    }

}