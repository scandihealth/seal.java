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

package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.AbstractModelTest;
import dk.sosi.seal.model.IdentityTokenBuilder;
import dk.sosi.seal.model.UserIDCard;
import dk.sosi.seal.model.XMLValidator;
import dk.sosi.seal.xml.XmlUtil;
import org.jdom.Attribute;
import org.jdom.Element;
import org.junit.Test;
import org.w3c.dom.Document;

import java.util.Date;

public class IdentityTokenResponseDOMBuilderTest extends AbstractModelTest {

    private static final Date notOnOrAfter = d(7);
    private static final Date notBefore = d(-2);

    @Test
    public void testBuilder() throws Exception {
        UserIDCard uidc = createUserIDCard();

        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setIssuer("http://pan.certifikat.dk/sts/services/SecurityTokenService");
        itb.setNotBefore(notBefore);
        itb.setNotOnOrAfter(notOnOrAfter);
        itb.setUserIdCard(uidc);
        itb.requireCertificateAsReference();
        itb.requireOrganizationName();
        itb.requireCvrNumberIdentifier();
        itb.requireCprNumber();
        itb.requireUserAuthorizationCode();

        IdentityTokenResponseDOMBuilder itrb = new IdentityTokenResponseDOMBuilder();
        itrb.setContext("urn:uuid:00000");
        itrb.setIdentityToken(itb.build());
        itrb.setRelatesTo("urn:uuid:99999999-0000-0000");

        Document identityTokenDoc = itrb.build();
        String xml = XmlUtil.node2String(identityTokenDoc);

        new XMLValidator() {

            @Override
            protected boolean ignore(String tag, String attribute) {
                if("MessageID".equals(tag)) {
                    return true; // Ignore this one, since it is generated based on contents
                }
                if("Assertion".equals(tag) && "IssueInstant".equals(attribute)) {
                    return true; // Ignore this one, as it is generated based on NOW.
                }
                if("Assertion".equals(tag) && "ID".equals(attribute)) {
                    return true; // Ignore this one, as it is a generated UUID.
                }
                if("Reference".equals(tag) && "URI".equals(attribute)) {
                    return true; // Ignore this one, as it is a generated UUID.
                }
                if("DigestValue".equals(tag)) {
                    return true; // Ignore this one, since it is generated based on contents
                }
                if("SignatureValue".equals(tag)) {
                    return true; // Ignore this one, since it is generated based on contents
                }
                if("AuthnStatement".equals(tag) && "AuthnInstant".equals(attribute)) {
                    return true; // Ignore this one, as it is generated based on NOW.
                }

                return false;
            }

            protected boolean assertAttributeValues(Element element, Attribute attribute, String expectedValue, String actualValue) {
                if("Conditions".equals(element.getName()) && "NotBefore".equals(attribute.getName())) {
                    expectedValue = XmlUtil.getDateFormat(true).format(notBefore);
                } else if("Conditions".equals(element.getName()) && "NotOnOrAfter".equals(attribute.getName())) {
                    expectedValue = XmlUtil.getDateFormat(true).format(notOnOrAfter);
                }

                return super.assertAttributeValues(element, attribute, expectedValue, actualValue);
            }

            @Override
            protected boolean assertTextContent(Element element, String expectedContents, String actualContents) {
                if("Created".equals(element.getName())) {
                    expectedContents = XmlUtil.getDateFormat(true).format(notBefore);
                } else if("Expires".equals(element.getName())) {
                    expectedContents = XmlUtil.getDateFormat(true).format(notOnOrAfter);
                }
                return super.assertTextContent(element, expectedContents, actualContents);
            }
        }.assertXML(xml, "OIO WS-Trust response.xml");
    }

    @Test
    public void testFaultMessage() throws Exception {
        IdentityTokenResponseDOMBuilder itrb = new IdentityTokenResponseDOMBuilder();
        itrb.setFaultCode("wst:FailedAuthentication");
        itrb.setFaultActor("http://sosi.dk/sts");
        itrb.setFaultString("Authentication failed: Token in request signed by untrusted party");
        itrb.setRelatesTo("urn:uuid:99999999-0000-0000.");

        Document identityTokenDoc = itrb.build();
        String xml = XmlUtil.node2String(identityTokenDoc);

        new XMLValidator() {

            @Override
            protected boolean ignore(String tag, String attribute) {
                if("MessageID".equals(tag)) {
                    return true; // Ignore this one, since it is generated based on contents
                }
                return false;
            }
        }.assertXML(xml, "OIO WS-Trust error response.xml");
    }
}