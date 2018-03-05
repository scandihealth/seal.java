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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/SecurityTokenResponseDOMBuilder.java $
 * $Id: SecurityTokenResponseDOMBuilder.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.SecurityTokenResponse;
import dk.sosi.seal.model.constants.IDValues;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * DomBuilder for STS SecurityTokenResponse. <p/> <b>This class should only be
 * accessed through model classes</b>
 * </p>
 * 
 * @author Peter Buus
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SecurityTokenResponseDOMBuilder extends SOAPMessageDOMBuilder {

	protected SAMLUtil samlUtil = new SAMLUtil();

    /**
     * Constructs a SOAP builder for SecurityTokenResponse.
     *
     * @param document
     *            the enclosing DOM document
     * @param securityTokenResponse
     *            The <code>SecurityTokenResponse</code> model element
     * @param vault
     *            The credential valt with system signature
     */
    @Deprecated
    public SecurityTokenResponseDOMBuilder(Document document, SecurityTokenResponse securityTokenResponse, CredentialVault vault) {

        super(document, securityTokenResponse, vault);
    }


    /**
	 * Constructs a SOAP builder for SecurityTokenResponse.
	 *  @param document
	 *            the enclosing DOM document
	 * @param securityTokenResponse
	 *            The <code>SecurityTokenResponse</code> model element
     * @param signatureProvider
     */
	public SecurityTokenResponseDOMBuilder(Document document, SecurityTokenResponse securityTokenResponse, SignatureProvider signatureProvider) {

		super(document, securityTokenResponse, signatureProvider);
	}

	/**
	 * Builds the document element.
	 */
	protected void _buildDOMDocument(Document document, Element header, Element body) {

		SecurityTokenResponse securityTokenResponse = (SecurityTokenResponse) getMessage();

		// Create wss:security element here
		Element wssSecurity = samlUtil.createSecurityHeader(document, header, securityTokenResponse);
		wssSecurity.setAttributeNS(null, IDValues.id, securityTokenResponse.getMessageID());
		header.appendChild(wssSecurity);

		if (securityTokenResponse.isFault()) {
			Element soapFault = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.FAULT_PREFIXED);

			Element faultcode = document.createElement(SOAPTags.FAULTCODE);
			faultcode.appendChild(document.createTextNode(securityTokenResponse.getFaultCode()));
			soapFault.appendChild(faultcode);

			Element faultstring = document.createElement(SOAPTags.FAULTSTRING);
			faultstring.appendChild(document.createTextNode(securityTokenResponse.getFaultString()));
			soapFault.appendChild(faultstring);

			Element faultActor = document.createElement(SOAPTags.FAULTACTOR);
			faultActor.appendChild(document.createTextNode(securityTokenResponse.getFaultActor()));
			soapFault.appendChild(faultActor);

			body.appendChild(soapFault);
		} else {
			WSTrustUtil wsTrustUtil = new WSTrustUtil();
			body.appendChild(wsTrustUtil.createSecurityTokenResponse(document, securityTokenResponse.getIDCard()));
		}
	}
}
