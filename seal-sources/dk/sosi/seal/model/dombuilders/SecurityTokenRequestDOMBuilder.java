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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/SecurityTokenRequestDOMBuilder.java $
 * $Id: SecurityTokenRequestDOMBuilder.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.SecurityTokenRequest;
import dk.sosi.seal.model.constants.IDValues;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a DOM tree representing a SecurityTokenRequest, given an
 * <code>SecurityTokenRequest</code> object.
 * <p>
 * The DOM builder primarilly builds the STS soap envelope including embedded
 * <code>IDCard</code> etc.
 * 
 * @author Peter Buus
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */

public class SecurityTokenRequestDOMBuilder extends SOAPMessageDOMBuilder {

    /**
     * Constructs the DOM builder for SecurityTokenRequests
     *
     * @param document
     *            the enclosing DOM document
     * @param securityTokenRequest
     *            the <code>SecurityTokenRequest</code> model element
     * @param vault
     *            The credential vault with system signature
     */
    @Deprecated
    public SecurityTokenRequestDOMBuilder(Document document, SecurityTokenRequest securityTokenRequest, CredentialVault vault) {

        super(document, securityTokenRequest, vault);
    }


    /**
	 * Constructs the DOM builder for SecurityTokenRequests
	 *  @param document
	 *            the enclosing DOM document
	 * @param securityTokenRequest
	 *            the <code>SecurityTokenRequest</code> model element
     * @param signatureProvider
     */
	public SecurityTokenRequestDOMBuilder(Document document, SecurityTokenRequest securityTokenRequest, SignatureProvider signatureProvider) {

		super(document, securityTokenRequest, signatureProvider);
	}

	/**
	 * Builds and returns the DOM element for this SAML request.
	 */
	protected void _buildDOMDocument(Document document, Element header, Element body) {

		SecurityTokenRequest securityTokenRequest = (SecurityTokenRequest) getMessage();

		SAMLUtil samlUtil = new SAMLUtil();
		// Create wss:security element here
		Element wssSecurity = samlUtil.createSecurityHeader(document, header, securityTokenRequest);
		wssSecurity.setAttributeNS(null, IDValues.id, securityTokenRequest.getMessageID());
		header.appendChild(wssSecurity);
		

		// SOSI ID-card as saml:Assertion
		WSTrustUtil wsTrustUtil = new WSTrustUtil();
		body.appendChild(wsTrustUtil.createSecurityTokenRequest(document, securityTokenRequest.getIDCard()));
	}
}
