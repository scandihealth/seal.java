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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/xml/TestAxisUtil.java $
 * $Id: TestAxisUtil.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.xml;

import dk.sosi.seal.model.constants.NameSpaces;
import junit.framework.TestCase;
import org.apache.axis.message.SOAPEnvelope;
import org.w3c.dom.Document;

import java.util.*;

public class TestAxisUtil extends TestCase {

    public static final String XML_DOCUMENT = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + "<soap:Envelope \n" + "\txmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" + "\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n" + " \txmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n"
            + " \txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n" + " \txmlns:medcom=\"http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd\"\n" + " \txmlns:sosi=\"http://www.sosi.dk/sosi/2006/04/sosi-1.0.xsd\"\n" + " \txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"
            + " \txmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"\n" + " \tid=\"Envelope\">\n" + "\t<soap:Header>\n" + "\t\t<wsse:Security>\n" + "\t\t\t<wsu:Timestamp>\n" + "\t\t\t\t<wsu:Created>2005-08-24T10:03:46</wsu:Created>\n" + "\t\t\t</wsu:Timestamp>\n" + "\t\t\t<saml:Assertion \n"
            + "\t\t\t\tid=\"IDCard\"\n" + "\t\t\t\tIssueInstant=\"2006-01-05T07:53:00\" \n" + "\t\t\t\tVersion=\"2.0\">\n" + "\t\t\t\t<saml:Issuer>some.system.name</saml:Issuer>\n" + "\t\t\t\t<saml:Subject>\n" + "\t\t\t\t\t<saml:NameID Format=\"medcom:cprnumber\">\n" + "\t\t\t\t\t\t1903701234\n" + "\t\t\t\t\t</saml:NameID>\n"
            + "\t\t\t\t\t<saml:SubjectConfirmation>\n" + "\t\t\t\t\t\t<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:2.0:cm:holder-of-key</saml:ConfirmationMethod>\n" + "\t\t\t\t\t\t<saml:SubjectConfirmationData>\n" + "\t\t\t\t\t\t\t<ds:KeyInfo>\n" + "\t\t\t\t\t\t\t\t<ds:KeyName>OCESSignature</ds:KeyName>\n" + "\t\t\t\t\t\t\t</ds:KeyInfo>\n"
            + "\t\t\t\t\t\t</saml:SubjectConfirmationData>\n" + "\t\t\t\t\t</saml:SubjectConfirmation>\n" + "\t\t\t\t</saml:Subject>\n" + "\t\t\t\t<saml:Conditions \n" + "\t\t\t\t\tNotBefore=\"2006-01-05T07:53:00.00\"\n" + "\t\t\t\t\tNotOnOrAfter=\"2006-01-06T07:53:00.000\"/>\n" + "\t\t\t\t<saml:AttributeStatement id=\"IDCardData\">\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"sosi:IDCardID\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>1234</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t\t<saml:Attribute Name=\"sosi:IDCardVersion\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>1.0</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"sosi:IDCardType\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>user</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t\t<saml:Attribute Name=\"sosi:AuthenticationLevel\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>4</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"sosi:OCESCertHash\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>ALiLaerBquie1/t6ykRKqLZe13Y=</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t</saml:AttributeStatement>\n" + "\t\t\t\t<saml:AttributeStatement id=\"UserLog\">\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserCivilRegistrationNumber\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>1903991234</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserGivenName\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>Jens</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserSurName\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>Hansen</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserEmailAddress\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>jh@nomail.dk</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserRole\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>PRAKTISERENDE_LAEGE</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserOccupation\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>Overlaege</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"medcom:UserAuthorizationCode\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>1234</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t</saml:AttributeStatement>\n" + "\t\t\t\t<saml:AttributeStatement id=\"SystemLog\">\n" + "\t\t\t\t\t<saml:Attribute Name=\"medcom:ITSystemName\">\n"
            + "\t\t\t\t\t\t<saml:AttributeValue>LaegeSystemet 3.0</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t\t<saml:Attribute Name=\"medcom:CareProviderID\"\n" + "\t\t\t\t\t\tNameFormat=\"medcom:ynumber\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>123456</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n"
            + "\t\t\t\t\t<saml:Attribute Name=\"medcom:CareProviderName\">\n" + "\t\t\t\t\t\t<saml:AttributeValue>Hansens praksis</saml:AttributeValue>\n" + "\t\t\t\t\t</saml:Attribute>\n" + "\t\t\t\t</saml:AttributeStatement>\n" + "\t\t\t</saml:Assertion>\n" + "\t\t</wsse:Security>\n" + "\t\t<medcom:Header>\n"
            + "\t\t\t<medcom:SecurityLevel>4</medcom:SecurityLevel>" + "\t\t\t<medcom:Linking>\n" + "\t\t\t\t<medcom:FlowID>aGQ5ZWxwcTA4N2ZubWM2ZA==</medcom:FlowID>\n" + "\t\t\t\t<medcom:MessageID>amRrMDk3d2doYXB2amY2cg==</medcom:MessageID>\n" + "\t\t\t</medcom:Linking>\n" + "\t\t\t<medcom:Priority>RUTINE</medcom:Priority>\n" + "\t\t</medcom:Header>\n"
            + "\t</soap:Header>\n" + "\t<soap:Body/>\n" + "</soap:Envelope>";

    public void testAddHeadersToSOAPEnvelope() throws Exception {
        addHeadersToSOAPEnvelopeTestMethod(true, new HashMap<String, String>(NameSpaces.SOSI_FAULT_NAMESPACES));
        addHeadersToSOAPEnvelopeTestMethod(false, new HashMap<String, String>(NameSpaces.SOSI_NAMESPACES));
    }

    @SuppressWarnings("unchecked")
    private void addHeadersToSOAPEnvelopeTestMethod(boolean isFault, Map<String, String> expectedNamespaces) throws Exception {
        SOAPEnvelope envelope = new SOAPEnvelope();
        Document doc = XmlUtil.readXml(new Properties(), XML_DOCUMENT, isFault);

        AxisUtil.addHeadersToSOAPEnvelope(envelope, doc, isFault);

        for (Iterator<String> nameSpaceIterator = envelope.getNamespacePrefixes(); nameSpaceIterator.hasNext();) {
            String type = nameSpaceIterator.next();
            expectedNamespaces.remove(type);
        }
        assertEquals("Expected empty map", 0, expectedNamespaces.size());

        assertEquals("ID property", "Envelope", envelope.getAttributeValue(envelope.createName("id")));

        Vector<String> headers = envelope.getHeaders();
        assertEquals("Expected one header", 1, headers.size());
    }

    public void testAddBodyToSOAPEnvelope() throws Exception {
        SOAPEnvelope envelope = new SOAPEnvelope();
        Document doc = XmlUtil.readXml(new Properties(), XML_DOCUMENT, false);

        AxisUtil.addBodyToSOAPEnvelope(envelope, doc);

        Vector<?> bodies = envelope.getBodyElements();
        assertEquals("Expected one body element", 1, bodies.size());
    }
}