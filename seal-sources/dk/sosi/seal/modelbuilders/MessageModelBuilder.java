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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/MessageModelBuilder.java $
 * $Id: MessageModelBuilder.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.Message;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.SecurityTokenRequest;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.text.ParseException;
import java.util.Date;

/**
 * Builds Message model objects from a DOM document.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public abstract class MessageModelBuilder {

	protected SOSIFactory factory;

	public MessageModelBuilder(SOSIFactory fac) {
		super();
		factory = fac;
	}

	/**
	 * Builds a Message objects from a DOM document.
	 *
	 * @param msg
	 *            The Message object that must be build.
	 * @param doc
	 *            The DOM document used for the Message.
	 */
	protected void buildModel(Message msg, Document doc) throws ModelBuildException {

		ModelPrefixResolver prefixResolver = new ModelPrefixResolver();

		// Get soap:Header
		Element elmSoapHeader = XmlUtil.selectSingleElement(doc, "//" + NameSpaces.NS_SOAP + ":Envelope/" + NameSpaces.NS_SOAP + ":Header", prefixResolver, true);

		// Get creation date
		Element elmCreated = XmlUtil.selectSingleElement(elmSoapHeader, NameSpaces.NS_WSSE + ":Security/" + NameSpaces.NS_WSU + ":Timestamp/" + NameSpaces.NS_WSU + ":Created", prefixResolver, true);

		String xmlTimestamp = XmlUtil.getTextNodeValue(elmCreated);
		Date created;
		try {
			created = XmlUtil.fromXMLTimeStamp(xmlTimestamp);
		} catch (ParseException e) {
			throw new ModelBuildException("Unable to parse timestamp from <wsu:Created>", e);
		}
		msg.setCreationDate(created);

		// DGWS Version
		String dgwsVersion = XmlUtil.isZuluTimeFormat(xmlTimestamp) ? DGWSConstants.VERSION_1_0_1 : DGWSConstants.VERSION_1_0;
		msg.setDGWSVersion(dgwsVersion);

		// IDCard - must be present on all requests
		IDCard idCard = new IDCardModelBuilder().buildModel(doc);
		if ((idCard == null) && (msg instanceof Request || msg instanceof SecurityTokenRequest))
			throw new ModelBuildException("No IDCard present in Request");

		if (idCard != null) msg.setIDCard(idCard);

		// MessageID
		if (doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.MESSAGE_ID).getLength() > 0) {
            NodeList messageIdchildNodes = doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.MESSAGE_ID).item(0).getChildNodes();
            if (messageIdchildNodes.getLength() == 0) {
                throw new ModelBuildException("DGWS violation: MessageID element must not be empty!");
            }
            String msgID = messageIdchildNodes.item(0).getNodeValue();
			msg.setMessageID(msgID);
		} else {
			// SecurityTokenRequest or SecurityTokenResponse
			String msgID = ((Element) doc.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY).item(0)).getAttribute(IDValues.id);
			msg.setMessageID(msgID);
		}

		// FlowID
		if (doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FLOW_ID).getLength() > 0) {
			NodeList flowIDs = doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FLOW_ID);
            NodeList flowIdChildNodes = flowIDs.item(0).getChildNodes();
            if (flowIdChildNodes.getLength() == 0) {
                throw new ModelBuildException("DGWS violation: FlowID element must not be empty!");
            }
            String flowID = flowIdChildNodes.item(0).getNodeValue();
			msg.setFlowID(flowID);
		}

        // Other headers
        NodeList headerList = doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED);
        if (headerList.getLength() > 0) {
            // get first element child node - we dont want ex. indentation nodes.
            for (int i = 0; i < headerList.item(0).getChildNodes().getLength(); i++) {
                Node n = headerList.item(0).getChildNodes().item(i);
                if(n.getNodeType() == Node.ELEMENT_NODE) {
                    Element e = (Element) n;
                    if(!(WSSETags.SECURITY.equals(e.getLocalName()) && NameSpaces.WSSE_SCHEMA.equals(e.getNamespaceURI())) &&
                       !(MedComTags.HEADER.equals(e.getLocalName()) && NameSpaces.MEDCOM_SCHEMA.equals(e.getNamespaceURI()))) {
                        msg.addNonSOSIHeader(e);
                    }
                }
            }
        }

		// Body
		NodeList bodyList = doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_UNPREFIXED);
		if (bodyList.getLength() > 0) {
            // get first element child node - we dont want ex. indentation nodes.
            for (int i = 0; i < bodyList.item(0).getChildNodes().getLength(); i++) {
                if(bodyList.item(0).getChildNodes().item(i).getNodeType() == Node.ELEMENT_NODE) {
                    msg.setBody((Element)bodyList.item(0).getChildNodes().item(i));
                    break;
                }
            }
		}
	}
}
