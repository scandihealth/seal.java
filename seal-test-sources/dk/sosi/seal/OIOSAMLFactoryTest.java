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
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.model.dombuilders.*;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.modelbuilders.OIOSAMLAssertionToIDCardRequestModelBuilder;
import dk.sosi.seal.pki.CertificateInfo;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSIFederation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.util.SOSITestUtils;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import static junit.framework.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLFactoryTest {

    private CredentialVault vocesVault;
    private CredentialVault mocesVault;
    private OIOSAMLFactory factory;

    @Before
    public void setUp() {
        vocesVault = CredentialVaultTestUtil.getVocesCredentialVault();
        mocesVault = CredentialVaultTestUtil.getCredentialVault();
        factory = new OIOSAMLFactory();
    }

    @Test
    public void testOIOSAMLToIDCardRequest() {

        OIOSAMLAssertionToIDCardRequestDOMBuilder domBuilder = factory.createOIOSAMLAssertionToIDCardRequestDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setOIOSAMLAssertion(parseOIOSAMLAssertion());
        domBuilder.setITSystemName("EMS");
        domBuilder.setUserAuthorizationCode("2345C");
        domBuilder.setUserEducationCode("7170");
        domBuilder.setUserGivenName("Fritz");
        domBuilder.setUserSurName("Müller");
        Document requestDoc = domBuilder.build();

        //requestDoc.getDocumentElement().getFirstChild().getFirstChild().setTextContent("FOO");
        //System.out.println(XmlUtil.node2String(requestDoc, true, true));

        OIOSAMLAssertionToIDCardRequest assertionToIDCardRequest = factory.createOIOSAMLAssertionToIDCardRequestModelBuilder().build(requestDoc);
        assertEquals("EMS", assertionToIDCardRequest.getITSystemName());
        assertEquals("2345C", assertionToIDCardRequest.getUserAuthorizationCode());
        assertEquals("7170", assertionToIDCardRequest.getUserEducationCode());
        assertEquals("Fritz", assertionToIDCardRequest.getUserGivenName());
        assertEquals("Müller", assertionToIDCardRequest.getUserSurName());
        assertEquals("http://sosi.dk", assertionToIDCardRequest.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", assertionToIDCardRequest.getAction());
        assertionToIDCardRequest.validateSignature();
        assertionToIDCardRequest.validateSignatureAndTrust(vocesVault);
        try {
            assertionToIDCardRequest.validateSignatureAndTrust(CredentialVaultTestUtil.getOCES2CredentialVault());
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), assertionToIDCardRequest.getSigningCertificate());

        OIOSAMLAssertion assertion = assertionToIDCardRequest.getOIOSAMLAssertion();
        assertEquals("25450442", assertion.getCvrNumberIdentifier());
        assertEquals("_020a271f-be04-4378-84ce-0a3ccae065c1", assertion.getID());
        assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());
        try {
            assertionToIDCardRequest.validateSignatureAndTrust(vocesVault);
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
    }

    @Test
    public void testOIOSAMLToIDCardResponse() {
        OIOSAMLAssertionToIDCardResponseDOMBuilder domBuilder = factory.createOIOSAMLAssertionToIDCardResponseDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setRelatesTo("1234");
        domBuilder.setContext("2345");
        IDCard idCard = createIDCard();
        domBuilder.setIDCard(idCard);
        Document responseDoc = domBuilder.build();

        //responseDoc.getDocumentElement().getFirstChild().getFirstChild().setTextContent("FOO");
        //System.out.println(XmlUtil.node2String(responseDoc, true, true));

        OIOSAMLAssertionToIDCardResponse assertionToIDCardResponse = factory.createOIOSAMLAssertionToIDCardResponseModelBuilder().build(responseDoc);
        assertEquals("1234", assertionToIDCardResponse.getRelatesTo());
        assertEquals("2345", assertionToIDCardResponse.getContext());
        assertEquals(idCard, assertionToIDCardResponse.getIDCard());
        assertEquals("http://sosi.dk", assertionToIDCardResponse.getAppliesTo());
        assertNull(assertionToIDCardResponse.getFaultActor());
        assertNull(assertionToIDCardResponse.getFaultCode());
        assertNull(assertionToIDCardResponse.getFaultString());
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), assertionToIDCardResponse.getSigningCertificate());

        assertionToIDCardResponse.validateSignature();
        assertionToIDCardResponse.validateSignatureAndTrust(getMockFederation());
        try {
            assertionToIDCardResponse.validateSignatureAndTrust(new SOSITestFederation(System.getProperties()));
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
    }

    @Test
    public void testOIOSAMLToIDCardErrorResponse() {
        OIOSAMLAssertionToIDCardResponseDOMBuilder domBuilder = factory.createOIOSAMLAssertionToIDCardResponseDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setRelatesTo("1234");
        domBuilder.setFaultActor("Server");
        domBuilder.setFaultCode("666");
        domBuilder.setFaultString("A horrible error occurred!");

        Document errorResponseDoc = domBuilder.build();
        OIOSAMLAssertionToIDCardResponse errorResponse = factory.createOIOSAMLAssertionToIDCardResponseModelBuilder().build(errorResponseDoc);
        assertEquals("1234", errorResponse.getRelatesTo());
        assertEquals("Server", errorResponse.getFaultActor());
        assertEquals("666", errorResponse.getFaultCode());
        assertEquals("A horrible error occurred!", errorResponse.getFaultString());
        assertNull(errorResponse.getIDCard());
        errorResponse.validateSignature();
        errorResponse.validateSignatureAndTrust(getMockFederation());

        try {
            errorResponse.validateSignatureAndTrust(new SOSIFederation(System.getProperties()));
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

        domBuilder.setIDCard(createIDCard());
        OIOSAMLAssertionToIDCardResponse wronglyBuiltErrorResponse = factory.createOIOSAMLAssertionToIDCardResponseModelBuilder().build(domBuilder.build());
        assertNull(wronglyBuiltErrorResponse.getIDCard());

    }

    @Test
    public void illustrateIDCardIssuing() {

        OIOSAMLAssertionToIDCardRequestDOMBuilder domBuilder = factory.createOIOSAMLAssertionToIDCardRequestDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setOIOSAMLAssertion(parseOIOSAMLAssertion());
        domBuilder.setITSystemName("Harmoni/EMS");
        Document requestDoc = domBuilder.build();

        OIOSAMLAssertionToIDCardRequest assertionToIDCardRequest = new OIOSAMLAssertionToIDCardRequestModelBuilder().build(requestDoc);

        // And STS should:
        // Check signature on request and that the signing certificate is issued by the correct OCES CA
        // Check signature and trust on assertion, that is check signing certificate is the IdPs
        // Check validity in time
        // Check assurance level
        // etc.

        UserInfo userInfo = buildUserInfo(assertionToIDCardRequest);
        OIOSAMLAssertion assertion = assertionToIDCardRequest.getOIOSAMLAssertion();
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, assertion.getCvrNumberIdentifier(), assertion.getOrganizationName());
        SystemInfo systemInfo = new SystemInfo(careProvider, assertionToIDCardRequest.getITSystemName());

        String certHash = SignatureUtil.getDigestOfCertificate(assertion.getUserCertificate());

        UserIDCard idCard = new UserIDCard(DGWSConstants.VERSION_1_0_1, AuthenticationLevel.MOCES_TRUSTED_USER, "SOSI-STS", systemInfo, userInfo, certHash, null, null, null);

        SOSIFactory sosiFactory = new SOSIFactory(vocesVault, System.getProperties());

        //The validity gets set to 24 hours - maybe the idcard should have a shorter lifetime?
        IDCard signedIdCard = sosiFactory.copyToVOCESSignedIDCard(idCard);
        Element idCardDocElement = signedIdCard.serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument());
        //System.out.println(XmlUtil.node2String(idCardDocElement, true, true));
    }

    @Test
    public void validateNemLoginAssertion() {
        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/NemLog-in_assertion_valid_signature.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(document.getDocumentElement());
        assertion.validateSignatureAndTrust(SOSITestUtils.getNewIdPTrustVault());
        assertEquals("3", assertion.getAssuranceLevel());
        assertEquals("25450442", assertion.getCvrNumberIdentifier());
        assertEquals("27304742", assertion.getRidNumberIdentifier());
    }

    private Federation getMockFederation() {
        return new SOSITestFederation(System.getProperties()) {
            @Override
            public boolean isValidSTSCertificate(X509Certificate certificate) {
                return vocesVault.getSystemCredentialPair().getCertificate().equals(certificate);
            }
        };
    }

    private UserInfo buildUserInfo(OIOSAMLAssertionToIDCardRequest request) {
        OIOSAMLAssertion assertion = request.getOIOSAMLAssertion();
        String cpr = "XXXXXXXX"; // Perform lookup based on assertion.getCvrNumberIdentifier() and assertion.getRidNumberIdentifier()
        String givenName;
        String surName;
        if (request.getUserGivenName() != null && request.getUserSurName() != null) {
            givenName = request.getUserGivenName();
            surName = request.getUserSurName();
        } else {
            // The IdP cannot split CommonName and neither should we (assertion.getSurName() returns null)
            givenName = assertion.getCommonName();
            surName = "-";
        }
        String email = assertion.getEmail();
        String occupation = null;
        String role = "YYYYY"; // Lookup based on CPR, use request.getUserEducationCode() to pick the right one (or validate)
        String authorizationCode = "ZZZZZ";// Lookup based on CPR, use request.getUserAuthorizationCode() to pick the right one (or validate)
        return new UserInfo(cpr, givenName, surName, email, occupation, role, authorizationCode);
    }

    private UserIDCard createIDCard() {
        SOSIFactory sosiFactory = new SOSIFactory(mocesVault, System.getProperties());
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "30808460", "Lægehuset på bakken");
        UserInfo userInfo = new UserInfo("1111111118", "Hans", "Dampf", null, null, "7170", "341KY");
        String alternativeIdentifier = new CertificateInfo(mocesVault.getSystemCredentialPair().getCertificate()).toString();
        UserIDCard userIDCard = sosiFactory.createNewUserIDCard("IT-System", userInfo, careProvider, AuthenticationLevel.MOCES_TRUSTED_USER, null, null, null, alternativeIdentifier);
        Request tmpRequest = sosiFactory.createNewRequest(false, "flow");
        tmpRequest.setIDCard(userIDCard);
        userIDCard.sign(tmpRequest.serialize2DOMDocument(), sosiFactory.getSignatureProvider());
        return userIDCard;
    }

    private OIOSAMLAssertion parseOIOSAMLAssertion() {
        String xml = SOSITestUtils.readXMLStreamAndRemoveFormatting(this.getClass().getResourceAsStream("/oiosaml-examples/test-new-nemlogin-authentication-assertion-2.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), xml, false);
        return new OIOSAMLAssertion(document.getDocumentElement());
    }

    @Test
    public void testIDCardToOIOSAMLRequest() {
        IDCardToOIOSAMLAssertionRequestDOMBuilder domBuilder = factory.createIDCardToOIOSAMLAssertionRequestDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setAudience("Sundhed.dk");
        UserIDCard idCard = createIDCard();
        domBuilder.setUserIDCard(idCard);
        Document requestDoc = domBuilder.build();

        IDCardToOIOSAMLAssertionRequest assertionRequest = factory.createIDCardToOIOSAMLAssertionRequestModelBuilder().build(requestDoc);
        assertEquals("Sundhed.dk", assertionRequest.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", assertionRequest.getAction());
        assertionRequest.validateSignature();
        assertionRequest.validateSignatureAndTrust(vocesVault);
        try {
            assertionRequest.validateSignatureAndTrust(CredentialVaultTestUtil.getOCES2CredentialVault());
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), assertionRequest.getSigningCertificate());

        assertEquals(idCard, assertionRequest.getUserIDCard());
        assertionRequest.getUserIDCard().validateSignature();
        assertionRequest.getUserIDCard().validateSignatureAndTrust(mocesVault);
        try {
            assertionRequest.getUserIDCard().validateSignatureAndTrust(new SOSIFederation(System.getProperties()));
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

    }

    @Test
    public void testIDCardToOIOSAMLRequestIDCardInHeader() {
        IDCardToOIOSAMLAssertionRequestDOMBuilder domBuilder = factory.createIDCardToOIOSAMLAssertionRequestDOMBuilder();
        domBuilder.requireIDCardInSOAPHeader();
        domBuilder.setAudience("Sundhed.dk");
        UserIDCard idCard = createIDCard();
        domBuilder.setUserIDCard(idCard);
        Document requestDoc = domBuilder.build();

        //System.out.println(XmlUtil.node2String(requestDoc, true, true));

        IDCardToOIOSAMLAssertionRequest assertionRequest = factory.createIDCardToOIOSAMLAssertionRequestModelBuilder().build(requestDoc);
        assertEquals("Sundhed.dk", assertionRequest.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", assertionRequest.getAction());
        try {
            assertionRequest.validateSignature();
        } catch (ModelBuildException e) {
            assertEquals("Could not find Liberty signature element", e.getMessage());
        }
        assertNull(assertionRequest.getSigningCertificate());

        assertEquals(idCard, assertionRequest.getUserIDCard());
        assertionRequest.getUserIDCard().validateSignature();
        assertionRequest.getUserIDCard().validateSignatureAndTrust(mocesVault);
        try {
            assertionRequest.getUserIDCard().validateSignatureAndTrust(new SOSIFederation(System.getProperties()));
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
    }

    @Test
    public void testIDCardToOIOSAMLRequestMissingIDCard() {
        IDCardToOIOSAMLAssertionRequestDOMBuilder domBuilder = factory.createIDCardToOIOSAMLAssertionRequestDOMBuilder();
        domBuilder.requireIDCardInSOAPHeader();
        domBuilder.setAudience("Sundhed.dk");
        UserIDCard idCard = createIDCard();
        domBuilder.setUserIDCard(idCard);
        Document requestDoc = domBuilder.build();

        Element idcardAssertion = (Element) requestDoc.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION).item(0);
        idcardAssertion.getParentNode().removeChild(idcardAssertion);

        IDCardToOIOSAMLAssertionRequest assertionRequest = factory.createIDCardToOIOSAMLAssertionRequestModelBuilder().build(requestDoc);
        assertEquals("Sundhed.dk", assertionRequest.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", assertionRequest.getAction());
        try {
            assertionRequest.validateSignature();
        } catch (ModelBuildException e) {
            assertEquals("Could not find Liberty signature element", e.getMessage());
        }
        assertNull(assertionRequest.getSigningCertificate());

        try {
            assertEquals(idCard, assertionRequest.getUserIDCard());
        } catch (ModelException e) {
            assertEquals("Malformed request: IDCard could not be found!", e.getMessage());
        }
    }

    @Test
    public void testOIOSAMLAssertionBuilder() {

        UserIDCard idCard = createIDCard();
        OIOSAMLAssertion assertion = createOIOSAMLAssertion(idCard);

        //System.out.println(XmlUtil.node2String(assertion.getDOM(), true, false));

        assertOIOSAMLAssertion(assertion, idCard);
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
        assertion.validateSignatureAndTrust(vocesVault);
    }

    private OIOSAMLAssertion createOIOSAMLAssertion(UserIDCard idCard) {
        OIOSAMLAssertionBuilder builder = factory.createOIOSAMLAssertionBuilder();
        builder.setSigningVault(vocesVault);
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

    @Test
    public void testIDCardToOIOSAMLResponse() {
        UserIDCard idCard = createIDCard();
        IDCardToOIOSAMLAssertionResponse response = createIdCardToOIOSAMLAssertionResponse(idCard);

        assertEquals("http://sundhed.dk", response.getAppliesTo());
        response.validateSignature();
        response.validateSignatureAndTrust(getMockFederation());

        try {
            response.validateSignatureAndTrust(new SOSIFederation(System.getProperties()));
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

        Element decryptedAssertionElm = EncryptionUtil.decryptAndDetach(response.getEncryptedOIOSAMLAssertionElement(), vocesVault.getSystemCredentialPair().getPrivateKey());
        OIOSAMLAssertion assertion = new OIOSAMLAssertion(decryptedAssertionElm);
        assertOIOSAMLAssertion(assertion, idCard);
    }

    private IDCardToOIOSAMLAssertionResponse createIdCardToOIOSAMLAssertionResponse(UserIDCard idCard) {
        IDCardToOIOSAMLAssertionResponseDOMBuilder builder = factory.createIDCardToOIOSAMLAssertionResponseDOMBuilder();
        builder.setSigningVault(vocesVault);
        builder.setOIOSAMLAssertion(createOIOSAMLAssertion(idCard));
        builder.setEncryptionKey(vocesVault.getSystemCredentialPair().getCertificate().getPublicKey());
        builder.setRelatesTo("1234");
        builder.setContext("5678");
        Document responseDoc = builder.build();

        //System.out.println(XmlUtil.node2String(responseDoc, true, false));

        //responseDoc = XmlUtil.readXml(System.getProperties(), XmlUtil.node2String(responseDoc), false);

        return factory.createIDCardToOIOSAMLAssertionResponseModelBuilder().build(responseDoc);
    }

    @Test
    public void testIDCardToOIOSAMLErrorResponse() {

        IDCardToOIOSAMLAssertionResponseDOMBuilder domBuilder = factory.createIDCardToOIOSAMLAssertionResponseDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setRelatesTo("1234");
        domBuilder.setFaultActor("Server");
        domBuilder.setFaultCode("666");
        domBuilder.setFaultString("A horrible error occurred!");

        Document errorResponseDoc = domBuilder.build();
        IDCardToOIOSAMLAssertionResponse errorResponse = factory.createIDCardToOIOSAMLAssertionResponseModelBuilder().build(errorResponseDoc);
        assertEquals("1234", errorResponse.getRelatesTo());
        assertEquals("Server", errorResponse.getFaultActor());
        assertEquals("666", errorResponse.getFaultCode());
        assertEquals("A horrible error occurred!", errorResponse.getFaultString());
        assertNull(errorResponse.getEncryptedOIOSAMLAssertionElement());
        errorResponse.validateSignature();
        errorResponse.validateSignatureAndTrust(getMockFederation());

        try {
            errorResponse.validateSignatureAndTrust(new SOSIFederation(System.getProperties()));
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

        domBuilder.setOIOSAMLAssertion(createOIOSAMLAssertion(createIDCard()));
        IDCardToOIOSAMLAssertionResponse wronglyBuiltErrorResponse = factory.createIDCardToOIOSAMLAssertionResponseModelBuilder().build(domBuilder.build());
        assertNull(wronglyBuiltErrorResponse.getEncryptedOIOSAMLAssertionElement());

    }

    @Test
    public void illustrateOIOSAMLAssertionIssuing() {

        IDCardToOIOSAMLAssertionRequestDOMBuilder domBuilder = factory.createIDCardToOIOSAMLAssertionRequestDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setAudience("Sundhed.dk");
        UserIDCard idCard = createIDCard();
        domBuilder.setUserIDCard(idCard);
        Document requestDoc = domBuilder.build();

        IDCardToOIOSAMLAssertionRequest assertionRequest = factory.createIDCardToOIOSAMLAssertionRequestModelBuilder().build(requestDoc);

        assertionRequest.validateSignature();

        UserIDCard userIDCard = assertionRequest.getUserIDCard();

        /* Validate userIDCard:
           - userIDCard.validateSignatureAndTrust(federation);
           - userIDCard.isValidInTime() == true
           - etc ...
        */

        String audience = assertionRequest.getAppliesTo();

        /* Retrieve from configuration for audience:
            - PublicKey
            - recipientURL
            - whether IDCard should be included in response
         */
        PublicKey audiencePublicKey = vocesVault.getSystemCredentialPair().getCertificate().getPublicKey();
        String recipientURL = "http://sundhed.dk/saml/SAMLAssertionConsumer";
        boolean includeIDCard = false;

        OIOSAMLAssertionBuilder builder = factory.createOIOSAMLAssertionBuilder();
        builder.setSigningVault(vocesVault);
        builder.setIssuer("Test STS");
        builder.setUserIdCard(userIDCard);
        Date now = new Date();
        builder.setNotBefore(now);
        builder.setNotOnOrAfter(new Date(now.getTime() + 60 * 60 * 1000));
        builder.setDeliveryNotOnOrAfter(new Date(now.getTime() + 5 * 60 * 1000));
        builder.setAudienceRestriction(audience);
        builder.setRecipientURL(recipientURL);
        if (includeIDCard) {
            builder.includeIDCardAsBootstrapToken();
        }

        OIOSAMLAssertion assertion = builder.build();

        IDCardToOIOSAMLAssertionResponseDOMBuilder responseBuilder = factory.createIDCardToOIOSAMLAssertionResponseDOMBuilder();
        responseBuilder.setSigningVault(vocesVault);
        responseBuilder.setEncryptionKey(audiencePublicKey);
        responseBuilder.setOIOSAMLAssertion(assertion);
        responseBuilder.setContext(assertionRequest.getContext());
        responseBuilder.setRelatesTo(assertionRequest.getMessageID());

        Document responseDoc = responseBuilder.build();

    }

    @Test
    public void illustrateUnsolicitedResponseConstruction() {
        IDCardToOIOSAMLAssertionResponse oiosamlAssertionResponse = createIdCardToOIOSAMLAssertionResponse(createIDCard());

        UnsolicitedResponseDOMBuilder builder = factory.createUnsolicitedResponseDOMBuilder();
        builder.setIssuer("Harmoni/EMS");
        builder.setEncryptedAssertion(oiosamlAssertionResponse.getEncryptedOIOSAMLAssertionElement());
        Document unsolicitedResponseDoc = builder.build();

        //System.out.println(XmlUtil.node2String(unsolicitedResponseDoc, true, true));

    }

    @Test
    public void testOIOBootstrapToIdentityTokenRequest() {
        OIOBootstrapToIdentityTokenRequestDOMBuilder domBuilder = factory.createOIOBootstrapToIdentityTokenRequestDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setCPRNumberClaim("2512484916");
        domBuilder.setAudience("https://fmk");

        InputSource inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/OIOBootstrapToIdentityToken/NemLog-In_bootstrap.xml"));
        Document document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        OIOBootstrapToken assertion = new OIOBootstrapToken(document.getDocumentElement());

        try {
            assertion.validateSignatureAndTrust(SOSITestUtils.getNewIdPTrustVault());
        } catch (ModelException e) {
            assertEquals("Signature on OIOSAMLAssertion is invalid", e.getMessage());
        }

        inputSource = new InputSource(this.getClass().getResourceAsStream("/oiosaml-examples/OIOBootstrapToIdentityToken/NemLog-In_bootstrap_valid_signature.xml"));
        document = XmlUtil.readXml(System.getProperties(), inputSource, false);
        assertion = new OIOBootstrapToken(document.getDocumentElement());

        try {
            assertion.validateSignatureAndTrust(SOSITestUtils.getNewIdPTrustVault());
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

        assertion.validateSignatureAndTrust(SOSITestUtils.getNewestIdPTrustVault());
        domBuilder.setOIOBootstrapToken(assertion);

        Document requestDoc = domBuilder.build();

        //System.out.println(XmlUtil.node2String(requestDoc, true, true));

        // write to string and parse to XML
        requestDoc = XmlUtil.readXml(System.getProperties(), XmlUtil.node2String(requestDoc), false);

        OIOBootstrapToIdentityTokenRequest assertionRequest = factory.createOIOBootstrapToIdentityTokenRequestModelBuilder().build(requestDoc);
        assertEquals("https://fmk", assertionRequest.getAppliesTo());
        assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", assertionRequest.getAction());
        assertEquals("2512484916", assertionRequest.getCPRNumberClaim());
        OIOBootstrapToken bootstrapToken = assertionRequest.getOIOBootstrapToken();
        assertEquals(assertion.getAudienceRestriction(), bootstrapToken.getAudienceRestriction());
        assertEquals(assertion.getSubjectNameID(), bootstrapToken.getSubjectNameID());

        assertionRequest.validateSignature();
        assertionRequest.validateSignatureAndTrust(vocesVault);
        try {
            assertionRequest.validateSignatureAndTrust(CredentialVaultTestUtil.getOCES2CredentialVault());
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), assertionRequest.getSigningCertificate());
    }

    @Test
    public void testOIOBootstrapToUnencryptedIdentityTokenResponse() {
        assertOIOBootstrapToIdentityTokenResponse(false);
    }

    @Test
    public void testOIOBootstrapToEncryptedIdentityTokenResponse() {
        assertOIOBootstrapToIdentityTokenResponse(true);
    }

    private void assertOIOBootstrapToIdentityTokenResponse(boolean encrypt) {
        OIOBootstrapToIdentityTokenResponseDOMBuilder domBuilder = factory.createOIOBootstrapToIdentityTokenResponseDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setRelatesTo("1234");
        domBuilder.setContext("2345");
        domBuilder.setIdentityToken(createIdentityToken());
        if (encrypt) {
            domBuilder.setEncryptionKey(vocesVault.getSystemCredentialPair().getCertificate().getPublicKey());
        }
        Document responseDoc = domBuilder.build();

        //System.out.println(XmlUtil.node2String(responseDoc, true, true));

        OIOBootstrapToIdentityTokenResponse bootstrapToIdentityResponse = factory.createOIOBootstrapToIdentityTokenResponseModelBuilder().build(responseDoc);
        assertEquals("https://fmk", bootstrapToIdentityResponse.getAppliesTo());
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), bootstrapToIdentityResponse.getSigningCertificate());

        IdentityToken identityToken = extractIdentityToken(encrypt, bootstrapToIdentityResponse);

        assertEquals("2512484916", identityToken.getCpr());
        assertEquals(null, identityToken.getUserEducationCode());
        assertEquals("3", identityToken.getAssuranceLevel());
        assertEquals("DK-SAML-2.0", identityToken.getSpecVersion());


        bootstrapToIdentityResponse.validateSignature();
        bootstrapToIdentityResponse.validateSignatureAndTrust(getMockFederation());
        try {
            bootstrapToIdentityResponse.validateSignatureAndTrust(new SOSITestFederation(System.getProperties()));
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
    }

    @Test
    public void testCitizenIdentityTokenBuilder() {
        IdentityToken identityToken = createIdentityToken();
        assertEquals("https://fmk", identityToken.getAudienceRestriction());
        assertEquals(null, identityToken.getITSystemName());
        assertEquals("2512484916", identityToken.getCpr());

        //System.out.println(XmlUtil.node2String(identityToken.getDOM(), true, true));
    }

    private IdentityToken createIdentityToken() {
        CitizenIdentityTokenBuilder tokenBuilder = factory.createCitizenIdentityTokenBuilder();
        tokenBuilder.setIssuer("http://sosi");
        tokenBuilder.setAudienceRestriction("https://fmk");
        Date now = new Date();
        tokenBuilder.setNotBefore(new Date(now.getTime() - 1000));
        tokenBuilder.setNotOnOrAfter(new Date(now.getTime() + 5 * 60 * 1000));
        tokenBuilder.setCprNumberAttribute("2512484916");
        tokenBuilder.setSubjectNameID("C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");
        tokenBuilder.setSubjectNameIDFormat(SAMLValues.NAMEID_FORMAT_X509_SUBJECT_NAME);
        tokenBuilder.setDeliveryNotOnOrAfter(new Date(now.getTime() + 10 * 1000));
        tokenBuilder.setRecipientURL("https://fmk");
        tokenBuilder.setSigningVault(vocesVault);
        // Just to have another cert
        tokenBuilder.setHolderOfKeyCertificate(CredentialVaultTestUtil.getOCES2CredentialVault().getSystemCredentialPair().getCertificate());

        return tokenBuilder.build();
    }

    @Test
    public void testEncryptedOIOSAMLAssertionToIdentityTokenRequest() {
        EncryptedOIOSAMLAssertionToIdentityTokenRequestDOMBuilder domBuilder = factory.createEncryptedOIOSAMLAssertionToIdentityTokenRequestDOMBuilder();
        domBuilder.setAudience("https://sosi");
        OIOSAMLAssertion assertion = createOIOSAMLAssertion(createIDCard());
        Element encryptedAssertionElm = createEncryptedAssertion(assertion);
        domBuilder.setEncryptedOIOSAMLAssertionElement(encryptedAssertionElm);
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setCPRNumberClaim("1111111118");

        Document requestDoc = domBuilder.build();

        //System.out.println(XmlUtil.node2String(requestDoc, true, true));

        EncryptedOIOSAMLAssertionToIdentityTokenRequest tokenRequest = factory.createEncryptedOIOSAMLAssertionToIdentityTokenRequestModelBuilder().build(requestDoc);
        assertEquals("1111111118", tokenRequest.getCPRNumberClaim());
        assertEquals("https://sosi", tokenRequest.getAppliesTo());
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), tokenRequest.getSigningCertificate());
        Element decryptedAssertionElement = EncryptionUtil.decryptAndDetach(tokenRequest.getEncryptedOIOSAMLAssertionElement(), vocesVault.getSystemCredentialPair().getPrivateKey());
        OIOSAMLAssertion decryptedAssertion = new OIOSAMLAssertion(decryptedAssertionElement);
        assertEquals(assertion.getSubjectNameID(), decryptedAssertion.getSubjectNameID());

        tokenRequest.validateSignature();
        tokenRequest.validateSignatureAndTrust(vocesVault);
        try {
            tokenRequest.validateSignatureAndTrust(mocesVault);
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }

    }

    @Test
    public void testEncryptedOIOSAMLAssertionToUnencryptedIdentityTokenResponse() {
        assertEncryptedOIOSAMLAssertionToIdentityTokenResponse(false);
    }

    @Test
    public void testEncryptedOIOSAMLAssertionToEncryptedIdentityTokenResponse() {
        assertEncryptedOIOSAMLAssertionToIdentityTokenResponse(true);
    }

    private void assertEncryptedOIOSAMLAssertionToIdentityTokenResponse(boolean encrypt) {
        EncryptedOIOSAMLAssertionToIdentityTokenResponseDOMBuilder domBuilder = factory.createEncryptedOIOSAMLAssertionToIdentityTokenResponseDOMBuilder();
        domBuilder.setSigningVault(vocesVault);
        domBuilder.setRelatesTo("1234");
        domBuilder.setContext("2345");
        domBuilder.setIdentityToken(createIdentityToken());
        if (encrypt) {
            domBuilder.setEncryptionKey(vocesVault.getSystemCredentialPair().getCertificate().getPublicKey());
        }
        Document responseDoc = domBuilder.build();

        //System.out.println(XmlUtil.node2String(responseDoc, true, true));

        EncryptedOIOSAMLAssertionToIdentityTokenResponse tokenResponse = factory.createEncryptedOIOSAMLAssertionToIdentityTokenResponseModelBuilder().build(responseDoc);
        assertEquals("https://fmk", tokenResponse.getAppliesTo());
        assertEquals(vocesVault.getSystemCredentialPair().getCertificate(), tokenResponse.getSigningCertificate());

        IdentityToken identityToken = extractIdentityToken(encrypt, tokenResponse);
        assertEquals("2512484916", identityToken.getCpr());
        assertEquals(null, identityToken.getUserEducationCode());
        assertEquals("3", identityToken.getAssuranceLevel());
        assertEquals("DK-SAML-2.0", identityToken.getSpecVersion());


        tokenResponse.validateSignature();
        tokenResponse.validateSignatureAndTrust(getMockFederation());
        try {
            tokenResponse.validateSignatureAndTrust(new SOSITestFederation(System.getProperties()));
            fail();
        } catch (ModelException e) {
            assertEquals("The certificate that signed the security token is not trusted!", e.getMessage());
        }
    }

    private IdentityToken extractIdentityToken(boolean encrypted, AbstractIdentityTokenResponse tokenResponse) {
        if (encrypted) {
            assertNull(tokenResponse.getIdentityToken());
            Element encryptedIdentityTokenElement = tokenResponse.getEncryptedIdentityTokenElement();
            return new IdentityToken(EncryptionUtil.decryptAndDetach(encryptedIdentityTokenElement, vocesVault.getSystemCredentialPair().getPrivateKey()));
        } else {
            assertNull(tokenResponse.getEncryptedIdentityTokenElement());
            return tokenResponse.getIdentityToken();
        }
    }


    private Element createEncryptedAssertion(OIOSAMLAssertion assertion) {
        String simpleXml = "<dummy-root/>";
        Document tempDoc = XmlUtil.readXml(System.getProperties(), simpleXml, false);
        Element dummyRoot = tempDoc.getDocumentElement();

        Element encryptedAssertionElm = tempDoc.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ENCRYPTED_ASSERTION_PREFIXED);
        dummyRoot.appendChild(encryptedAssertionElm);
        Element assertionElm = (Element) tempDoc.importNode(assertion.getDOM().getDocumentElement(), true);
        encryptedAssertionElm.appendChild(assertionElm);

        EncryptionUtil.encrypt(assertionElm, vocesVault.getSystemCredentialPair().getCertificate().getPublicKey());

        //System.out.println(XmlUtil.node2String(tempDoc, true, true));

        return (Element) dummyRoot.getFirstChild();
    }
}
