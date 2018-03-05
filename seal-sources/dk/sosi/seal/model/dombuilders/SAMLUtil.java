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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/SAMLUtil.java $
 * $Id: SAMLUtil.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.Message;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.model.constants.IDValues;
import dk.sosi.seal.model.constants.MedComTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.modelbuilders.ModelPrefixResolver;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.TransformerException;

/**
 * Utility method for handling SAML.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SAMLUtil {

	public static final String VERSION = "2.0";
	private static final String urn = "urn:oasis:names:tc:SAML:2.0:status:";
	public static final String[] status = { urn + "Success", urn + "AuthFailed" };

	public Element createSAMLAttributeStatement(Document document, String id) {
		Element attr = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, NameSpaces.NS_SAML + ":AttributeStatement");
		attr.setAttributeNS(null, IDValues.id, id);
		return attr;
	}

	public Element createSAMLAttribute(Document document, String name, String value, Element parent) {

		return createAttribute(document, NameSpaces.NS_SAML, name, value, parent);
	}

	public Element createMedcomLinking(Document document, Element parent, Message msg) {

		Element linking = (Element) parent.appendChild(document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.LINKING_PREFIXED));

		if (msg.getFlowID() != null) {
			Element flowID = (Element) linking.appendChild(document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FLOW_ID_PREFIXED));
			flowID.appendChild(document.createTextNode(msg.getFlowID()));
		}

		Element messageID = (Element) linking.appendChild(document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.MESSAGE_ID_PREFIXED));
		messageID.appendChild(document.createTextNode(msg.getMessageID()));

		return linking;
	}

	public Element createSecurityHeader(Document document, Element parent, Message msg) {

		Element wssSecurity = document.createElementNS(NameSpaces.WSSE_SCHEMA, NameSpaces.NS_WSSE + ":Security");
		parent.appendChild(wssSecurity);

		// <wsu:Timestamp>
		// <wsu:Created>2005-08-24T10:03:46</wsu:Created>
		// </wsu:Timestamp>
		Element eCreated = document.createElementNS(NameSpaces.WSU_SCHEMA, NameSpaces.NS_WSU + ":Created");
        boolean useZuluTime = DGWSConstants.VERSION_1_0_1.equals(msg.getDGWSVersion());
		eCreated.appendChild(document.createTextNode(XmlUtil.toXMLTimeStamp(msg.getCreationDate(), useZuluTime)));
		Element eTimestamp = document.createElementNS(NameSpaces.WSU_SCHEMA, NameSpaces.NS_WSU + ":Timestamp");
		eTimestamp.appendChild(eCreated);
		wssSecurity.appendChild(eTimestamp);
		return wssSecurity;
	}

	public Element createSecurityLevel(Document document, Element parent, int securityLevel) {

		Element elmSecurityLevel = document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.SECURITY_LEVEL_PREFIXED);
		elmSecurityLevel.appendChild(document.createTextNode(Integer.toString(securityLevel)));
		parent.appendChild(elmSecurityLevel);
		return elmSecurityLevel;
	}

	public Element createMedcomHeader(Document document, Element parent) {

		Element elmMedComHeader = document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.HEADER_PREFIXED);
		parent.appendChild(elmMedComHeader);
		return elmMedComHeader;
	}

	public Element fetchSamlAttributeValue(Document doc, String attrName) throws TransformerException {
        Element systemLog = fetchSamlAttributeStatement(doc,IDValues.SYSTEM_LOG);
	    String xpath = "//"+NameSpaces.NS_SAML + ":Attribute[@Name='"+attrName+"']/"+NameSpaces.NS_SAML + ":AttributeValue";
        return XmlUtil.selectSingleElement(systemLog, xpath, new ModelPrefixResolver(), false);
	}

	public Element fetchSamlAttributeStatement(Document doc, String statementID) {
        String xpath = "//"+NameSpaces.NS_SAML + ":AttributeStatement[@id='"+statementID+"']";
        return XmlUtil.selectSingleElement(doc, xpath, new ModelPrefixResolver(), false);
	}

	// ======================================
	// Private operations ...
	// ======================================

	private Element createAttribute(Document document, String namespace, String name, String value, Element parent) {

		Element messageID = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, namespace + ":Attribute");
		messageID.setAttributeNS(null, "Name", name);
		parent.appendChild(messageID);
		Element messageIDValue = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, namespace + ":AttributeValue");
		messageID.appendChild(messageIDValue);
		messageIDValue.appendChild(document.createTextNode(value));
		return messageID;
	}

}
