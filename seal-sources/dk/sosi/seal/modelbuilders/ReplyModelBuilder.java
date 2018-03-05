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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/ReplyModelBuilder.java $
 * $Id: ReplyModelBuilder.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.Reply;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.transform.TransformerException;
import java.util.ArrayList;
import java.util.List;

/**
 * Build the Model assuming compliance with DGWS 1.0 format
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class ReplyModelBuilder extends MessageModelBuilder {

	public ReplyModelBuilder(SOSIFactory fac) {
		super(fac);
	}

	/**
	 * Builds a Reply objects from a DOM document.
	 *
	 * @param doc
	 *            The DOM document used for the Reply.
	 */
	public Reply buildModel(Document doc) throws ModelBuildException {

		ModelPrefixResolver prefixResolver = new ModelPrefixResolver();

		// Get soap:Header
		Element elmSoapHeader = XmlUtil.selectSingleElement(doc, "//" + NameSpaces.NS_SOAP + ":Envelope/" + NameSpaces.NS_SOAP + ":Header", prefixResolver, true);
		// Get creation date
		Element elmCreated = XmlUtil.selectSingleElement(elmSoapHeader, NameSpaces.NS_WSSE + ":Security/" + NameSpaces.NS_WSU + ":Timestamp/" + NameSpaces.NS_WSU + ":Created", prefixResolver, true);

		String xmlTimestamp = XmlUtil.getTextNodeValue(elmCreated);
		String dgwsVersion = XmlUtil.isZuluTimeFormat(xmlTimestamp) ? DGWSConstants.VERSION_1_0_1 : DGWSConstants.VERSION_1_0;


		Element elmMedcomHeader = XmlUtil.selectSingleElement(elmSoapHeader, MedComTags.HEADER_PREFIXED, prefixResolver, true);
		// Get medcom:Linking
		Element elmLinking = XmlUtil.selectSingleElement(elmMedcomHeader, MedComTags.LINKING_PREFIXED, prefixResolver, true);
		// Get the values of the (potentially) 3 elements in the medcom:Linking
		// root
		String inResponseToMessageID = null;
		String flowID = null;

		Element elmInResponseToMessageId = XmlUtil.selectSingleElement(elmLinking, MedComTags.IN_RESPONSE_TO_MESSAGE_ID_PREFIXED, prefixResolver, false);
		if (elmInResponseToMessageId != null) {
			inResponseToMessageID = XmlUtil.getTextNodeValue(elmInResponseToMessageId);
		}
		Element elmFlowID = XmlUtil.selectSingleElement(elmLinking, MedComTags.FLOW_ID_PREFIXED, prefixResolver, false);
		if (elmFlowID != null) {
			flowID = XmlUtil.getTextNodeValue(elmFlowID);
		}

		// medcom:FlowStatus
		Element elmFlowStatus, elmMedcomFaultCode, elmFaultString, elmFaultCode;
		Reply reply;

		elmFlowStatus = XmlUtil.selectSingleElement(elmMedcomHeader, MedComTags.FLOW_STATUS_PREFIXED, prefixResolver, false);

		if (elmFlowStatus == null) {
			// This could be a fault. Check for soap:Fault in the body.
			Element fault = XmlUtil.selectSingleElement(doc, "//" + SOAPTags.BODY_PREFIXED + '/' + SOAPTags.FAULT_PREFIXED, prefixResolver, false);
			if (fault == null) {
				throw new ModelBuildException("No " + MedComTags.FLOW_STATUS_PREFIXED + " present in document and no " + SOAPTags.FAULT_PREFIXED + " in "
						+ SOAPTags.BODY_PREFIXED + "!");
			}

            elmFaultCode = XmlUtil.selectSingleElement(fault, SOAPTags.FAULTCODE, prefixResolver, false);
            Element detail = XmlUtil.selectSingleElement(fault, SOAPTags.DETAIL, prefixResolver, false);
            List<Element> extraFaultDetails = extractExtraFaultDetails(detail, prefixResolver);
            elmMedcomFaultCode = XmlUtil.selectSingleElement(detail, MedComTags.FAULT_CODE_PREFIXED, prefixResolver, false);
            elmFaultString = XmlUtil.selectSingleElement(fault, SOAPTags.FAULTSTRING, prefixResolver, false);

            if (elmFaultCode == null)
				throw new ModelBuildException("No " + SOAPTags.FAULTCODE + " in " + SOAPTags.FAULT_PREFIXED);

			if (elmMedcomFaultCode == null)
				throw new ModelBuildException("No " + MedComTags.FAULT_CODE_PREFIXED + " in " + SOAPTags.FAULT_PREFIXED);

			if (elmFaultString == null)
				throw new ModelBuildException("No " + SOAPTags.FAULTSTRING + " in " + SOAPTags.FAULT_PREFIXED);

			reply = factory.createNewErrorReply(dgwsVersion, inResponseToMessageID, flowID, XmlUtil.getTextNodeValue(elmMedcomFaultCode),
					XmlUtil.getTextNodeValue(elmFaultString), extraFaultDetails);
		} else {
			reply = factory.createNewReply(dgwsVersion, inResponseToMessageID, flowID, XmlUtil.getTextNodeValue(elmFlowStatus));
		}

		// Message parameters
		super.buildModel(reply, doc);

		// Validate Signature
		SignatureUtil.validateAllSignatures(reply, doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE), factory.getFederation(), factory.getCredentialVault(),true);

		return reply;
	}

    private List<Element> extractExtraFaultDetails(Element detail, ModelPrefixResolver prefixResolver) {
        try {
            NodeList nodelist = XPathAPI.eval(detail, "*[not(self::" + MedComTags.FAULT_CODE_PREFIXED + ")]", prefixResolver).nodelist();
            List<Element> extraFaultDetails = new ArrayList<Element>(nodelist.getLength());
            for (int i = 0; i < nodelist.getLength(); i++) {
                extraFaultDetails.add((Element) nodelist.item(i));
            }
            return extraFaultDetails;
        } catch (TransformerException e) {
            throw new ModelBuildException("Could not determine extra fault details", e);
        }
    }
}
