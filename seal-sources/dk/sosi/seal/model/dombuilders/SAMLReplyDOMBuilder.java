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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/SAMLReplyDOMBuilder.java $
 * $Id: SAMLReplyDOMBuilder.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.Reply;
import dk.sosi.seal.model.constants.MedComTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * DomBuilder for SOSI compliant SAML replies. <p/> <b>This class should only be
 * accessed through model classes</b>
 * </p>
 * 
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SAMLReplyDOMBuilder extends SOAPMessageDOMBuilder {

	protected SAMLUtil samlUtil = new SAMLUtil();

    /**
     * Constructs a SOAP builder for SAML replies.
     *
     * @param document
     *            the enclosing DOM document
     * @param reply
     *            The <code>Reply</code> model element
     * @param vault
     *            The credential valt with system signature
     */
    @Deprecated
    public SAMLReplyDOMBuilder(Document document, Reply reply, CredentialVault vault) {

        super(document, reply, vault);
    }

	/**
	 * Constructs a SOAP builder for SAML replies.
	 * 
	 * @param document
	 *            the enclosing DOM document
	 * @param reply
	 *            The <code>Reply</code> model element
	 * @param signatureProvider
	 *            The SignatureProvider with system signature
	 */
	public SAMLReplyDOMBuilder(Document document, Reply reply, SignatureProvider signatureProvider) {

		super(document, reply, signatureProvider);
	}

	/**
	 * Builds the document element.
	 */
	protected void _buildDOMDocument(Document document, Element header, Element body) {

		Reply reply = (Reply) getMessage();

		// Create wss:security element here
		Element wssSecurity = samlUtil.createSecurityHeader(document, header, reply);

		if (reply.getIDCard() != null) {
			wssSecurity.appendChild(reply.getIDCard().serialize2DOMDocument(reply.getFactory(), document));
		}

		Element medComHeader = samlUtil.createMedcomHeader(document, header);

		// Medcom attributes
		if (reply.getIDCard() != null) {
			samlUtil.createSecurityLevel(document, medComHeader, reply.getIDCard().getAuthenticationLevel().getLevel());
		} else {
			samlUtil.createSecurityLevel(document, medComHeader, 1);
		}
		Element medcomLinking = samlUtil.createMedcomLinking(document, medComHeader, reply);
		Element inResponseToMessageID = (Element) medcomLinking.appendChild(document.createElementNS(
				NameSpaces.MEDCOM_SCHEMA,
					MedComTags.IN_RESPONSE_TO_MESSAGE_ID_PREFIXED));
		inResponseToMessageID.appendChild(document.createTextNode(reply.getRequestID()));

		// Set FlowStatus
		if (reply.isFault()) {
			Element soapFault = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.FAULT_PREFIXED);

			Element faultcode = document.createElement(SOAPTags.FAULTCODE);
			faultcode.appendChild(document.createTextNode("Server"));
			soapFault.appendChild(faultcode);

			Element detail = document.createElement(SOAPTags.DETAIL);
			Element medcomFaultCode = document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FAULT_CODE_PREFIXED);
			medcomFaultCode.appendChild(document.createTextNode(reply.getFaultCode()));
			detail.appendChild(medcomFaultCode);
            for (Element extraDetail : reply.getExtraFaultDetails()) {
                detail.appendChild(document.importNode(extraDetail, true));
            }
			soapFault.appendChild(detail);

			Element faultstring = document.createElement(SOAPTags.FAULTSTRING);
			faultstring.appendChild(document.createTextNode(reply.getFaultString()));
			soapFault.appendChild(faultstring);

			body.appendChild(soapFault);
		} else {
			Element flowStatus = document.createElementNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FLOW_STATUS_PREFIXED);
			flowStatus.appendChild(document.createTextNode(reply.getFlowStatus()));
			medComHeader.appendChild(flowStatus);
		}
	}
}
