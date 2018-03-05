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

import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Date;

import static org.junit.Assert.*;

public class IdentityTokenTest extends AbstractModelTest {
    
    private static final Date notBefore = d(-5);
    private static final Date notOnOrAfter = d(5);

    @Test
    public void simpleITTest() {
        UserIDCard userIDCard = createUserIDCard();
        IdentityToken it = createIdentityToken(true, true, true, true, true, true, true, userIDCard);

        assertEquals("AudienceRestriction", "http://fmk-online.dk", it.getAudienceRestriction());
        assertEquals("AuthorizationCode", EXPECTED_AUTHORIZATIONCODE, it.getAuthorizationCode());
        assertEquals("CPR", EXPECTED_CPR, it.getCpr());
        assertEquals("CvrNumberIdentifier", EXPECTED_CVR, it.getCvrNumberIdentifier());
        assertEquals("Email", EXPECTED_EMAIL, it.getEmail());
        assertEquals("CommonName", EXPECTED_GIVENNAME + " " + EXPECTED_SURNAME, it.getCommonName());
        assertEquals("NotBefore", notBefore, it.getNotBefore());
        assertEquals("NotOnOrAfter", notOnOrAfter, it.getNotOnOrAfter());
        assertEquals("OrganizationName", EXPECTED_ORGANIZATION, it.getOrganizationName());
        assertEquals("SurName", EXPECTED_SURNAME, it.getSurName());
        assertEquals("Issuer", EXPECTED_ISSUER, it.getIssuer());
        assertTrue("ID", it.getID().startsWith("_"));
        assertEquals("AssuranceLevel", EXPECTED_ASSURANCELEVEL, it.getAssuranceLevel());
        assertEquals("SpecVersion", EXPECTED_SPECVERSION, it.getSpecVersion());
        assertEquals("ITSystemName", EXPECTED_ITSYSTEMNAME, it.getITSystemName());
        assertEquals("UserEducationCode", EXPECTED_USEREDUCATIONCODE, it.getUserEducationCode());
        assertEquals("UserAuthenticationInstant", XmlUtil.toXMLTimeStamp(userIDCard.getCreatedDate(), true), XmlUtil.toXMLTimeStamp(it.getUserAuthenticationInstant(), true));
    }

    @Test
    public void simpleITWithoutOptional() {
        UserIDCard userIDCard = createUserIDCard();
        IdentityToken it = createIdentityToken(false, false, false, true, false, false, false, userIDCard);

        assertEquals("AudienceRestriction", "http://fmk-online.dk", it.getAudienceRestriction());
        assertNull("AuthorizationCode", it.getAuthorizationCode());
        assertNull("CPR", it.getCpr());
        assertNull("CvrNumberIdentifier", it.getCvrNumberIdentifier());
        assertEquals("Email", EXPECTED_EMAIL, it.getEmail());
        assertEquals("CommonName", EXPECTED_GIVENNAME + " " + EXPECTED_SURNAME, it.getCommonName());
        assertEquals("NotBefore", notBefore, it.getNotBefore());
        assertEquals("NotOnOrAfter", notOnOrAfter, it.getNotOnOrAfter());
        assertNull("OrganizationName", it.getOrganizationName());
        assertEquals("SurName", EXPECTED_SURNAME, it.getSurName());
        assertTrue("ID", it.getID().startsWith("_"));
        assertEquals("AssuranceLevel", EXPECTED_ASSURANCELEVEL, it.getAssuranceLevel());
        assertEquals("SpecVersion", EXPECTED_SPECVERSION, it.getSpecVersion());
        assertNull("ITSystemName", it.getITSystemName());
        assertNull("UserEducationCode", it.getUserEducationCode());
        assertEquals("UserAuthenticationInstant", XmlUtil.toXMLTimeStamp(userIDCard.getCreatedDate(), true), XmlUtil.toXMLTimeStamp(it.getUserAuthenticationInstant(), true));
    }

    @Test
    public void testDeflation() throws Exception {
        IdentityToken it_original = createIdentityToken(true, true, true, true, false, false, false, createUserIDCard());

        String url = it_original.createURLBuilder().encode();

        IdentityToken it_inflated = IdentityTokenBuilder.constructFromURLString(url, getMockFederation());

        compareIdentityTokens(it_original, it_inflated);
    }

    @Test
    public void testDOMManipulation() {
        UserIDCard userIDCard = createUserIDCard();
        IdentityToken it = createIdentityToken(true, true, true, true, false, true, false, userIDCard);

        // Assert the original object
        assertEquals("AudienceRestriction", "http://fmk-online.dk", it.getAudienceRestriction());
        assertEquals("AuthorizationCode", EXPECTED_AUTHORIZATIONCODE, it.getAuthorizationCode());
        assertEquals("CPR", EXPECTED_CPR, it.getCpr());
        assertEquals("CvrNumberIdentifier", EXPECTED_CVR, it.getCvrNumberIdentifier());
        assertEquals("Email", EXPECTED_EMAIL, it.getEmail());
        assertEquals("CommonName", EXPECTED_GIVENNAME + " " + EXPECTED_SURNAME, it.getCommonName());
        assertEquals("NotBefore", notBefore, it.getNotBefore());
        assertEquals("NotOnOrAfter", notOnOrAfter, it.getNotOnOrAfter());
        assertEquals("OrganizationName", EXPECTED_ORGANIZATION, it.getOrganizationName());
        assertEquals("SurName", EXPECTED_SURNAME, it.getSurName());
        assertEquals("UserAuthenticationInstant", XmlUtil.toXMLTimeStamp(userIDCard.getCreatedDate(), true), XmlUtil.toXMLTimeStamp(it.getUserAuthenticationInstant(), true));

        // Modify the DOM
        Document doc = it.getDOM();

        TestDOMInfoExtractor tdie = new TestDOMInfoExtractor((Element)doc.getFirstChild());

        Element samlConditionsElm = tdie.getTag(SAMLTags.assertion, SAMLTags.conditions);
        samlConditionsElm.setAttributeNS(null, "NotBefore", XmlUtil.getDateFormat(true).format(new Date()));

        // Assert the original object is unmodified.
        assertEquals("AudienceRestriction", "http://fmk-online.dk", it.getAudienceRestriction());
        assertEquals("AuthorizationCode", EXPECTED_AUTHORIZATIONCODE, it.getAuthorizationCode());
        assertEquals("CPR", EXPECTED_CPR, it.getCpr());
        assertEquals("CvrNumberIdentifier", EXPECTED_CVR, it.getCvrNumberIdentifier());
        assertEquals("Email", EXPECTED_EMAIL, it.getEmail());
        assertEquals("CommonName", EXPECTED_GIVENNAME + " " + EXPECTED_SURNAME, it.getCommonName());
        assertEquals("NotBefore", notBefore, it.getNotBefore());
        assertEquals("NotOnOrAfter", notOnOrAfter, it.getNotOnOrAfter());
        assertEquals("OrganizationName", EXPECTED_ORGANIZATION, it.getOrganizationName());
        assertEquals("SurName", EXPECTED_SURNAME, it.getSurName());
        assertEquals("UserAuthenticationInstant", XmlUtil.toXMLTimeStamp(userIDCard.getCreatedDate(), true), XmlUtil.toXMLTimeStamp(it.getUserAuthenticationInstant(), true));
    }

    @Test
    public void testSignatureCertificateIncluded() {
        IdentityToken identityToken = createIdentityToken(false, false, false, false, false, false, false, createUserIDCard());
        assertSignature(identityToken);
    }

    @Test
    public void testSignatureCertificateAsReference() {
        IdentityToken identityToken = createIdentityToken(false, false, false, true, false, false, false, createUserIDCard());
        assertSignature(identityToken);
    }

    private void assertSignature(IdentityToken identityToken) {
        identityToken.validateSignature(getMockFederation());
    }

    private void compareIdentityTokens(IdentityToken it_original, IdentityToken it_inflated) throws Exception {
        Method[] methods = IdentityToken.class.getDeclaredMethods();

        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if(!Modifier.isPublic(method.getModifiers())) {
                continue;
            }
            if(!method.getName().startsWith("get")) {
                continue;
            }
            if(method.getName().equals("getDOM")) {
                continue;
            }

            Object expectedValue = method.invoke(it_original);
            Object actualValue = method.invoke(it_inflated);

            assertEquals("Value of method (" + method.getName() + ")", expectedValue, actualValue);
        }
    }

    private IdentityToken createIdentityToken(boolean addCVR, boolean addOrganization, boolean addCPR, boolean includeCertAsReference, boolean addITSystemName, boolean addUserAuthorizationCode, boolean addUserEducationCode, UserIDCard userIDCard) {
        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setNotBefore(notBefore);
        itb.setNotOnOrAfter(notOnOrAfter);
        itb.setUserIdCard(userIDCard);
        itb.setIssuer(EXPECTED_ISSUER);
        if (includeCertAsReference) {
            itb.requireCertificateAsReference();
        }
        if(addCVR) {
            itb.requireCvrNumberIdentifier();
        }
        if(addOrganization) {
            itb.requireOrganizationName();
        }
        if(addCPR) {
            itb.requireCprNumber();
        }
        if (addITSystemName) {
            itb.requireITSystemName();
        }
        if (addUserAuthorizationCode) {
            itb.requireUserAuthorizationCode();
        }
        if (addUserEducationCode) {
            itb.requireUserEducationCode();
        }
        return itb.build();
    }
}