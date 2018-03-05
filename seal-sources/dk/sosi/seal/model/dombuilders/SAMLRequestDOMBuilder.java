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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/SAMLRequestDOMBuilder.java $
 * $Id: SAMLRequestDOMBuilder.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.constants.MedComTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a DOM tree representing a SAML request, given a <code>Request</code>
 * object.
 * <p>
 * The DOM builder primarilly builds the SOSI envelope including embedded
 * <code>IDCard</code> etc. The body element is not built in this builder but
 * is merely passed (in the constructor) and embedded in the SOAP envelope.
 * 
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */

public class SAMLRequestDOMBuilder extends SOAPMessageDOMBuilder {

    /**
     * Constructs the DOM builder for SAML requests.
     *
     * @param document
     *            the enclosing DOM document
     * @param request
     *            the <code>Request</code> model element
     * @param vault
     *            The credential valt with system signature
     */
   @Deprecated
    public SAMLRequestDOMBuilder(Document document, Request request, CredentialVault vault) {

        super(document, request, vault);
    }

    /**
	 * Constructs the DOM builder for SAML requests.
	 * 
	 * @param document
	 *            the enclosing DOM document
	 * @param request
	 *            the <code>Request</code> model element
	 * @param signatureProvider
	 *            The SignatureProvider with system signature
	 */
	public SAMLRequestDOMBuilder(Document document, Request request, SignatureProvider signatureProvider) {

		super(document, request, signatureProvider);
	}

	/**
	 * Builds and returns the DOM element for this SAML request.
	 */
	protected void _buildDOMDocument(Document document, Element header, Element body) {

		Request request = (Request) getMessage();

		SAMLUtil samlUtil = new SAMLUtil();
		// Create wss:security element here
		Element wssSecurity = samlUtil.createSecurityHeader(document, header, request);

		// SOSI ID-card as saml:Assertion
		IDCard idCard = request.getIDCard();

		if(idCard == null) throw new ModelException("No Idcard present in request");
		wssSecurity.appendChild(idCard.serialize2DOMDocument(request.getFactory(), document));

		Element medComHeader = samlUtil.createMedcomHeader(document, header);

		// medcom:SecurityLevel
		int authLevel = idCard.getAuthenticationLevel().getLevel();
		samlUtil.createSecurityLevel(document, medComHeader, authLevel);

		// medcom:Linking
		samlUtil.createMedcomLinking(document, medComHeader, request);

		// medcom:RequireNonRepudiationReceipt
		Element nrr = (Element) medComHeader.appendChild(document.createElementNS(
				NameSpaces.MEDCOM_SCHEMA,
					MedComTags.REQUIRE_NON_REPUDIATION_RECEIPT_PREFIXED));
		nrr.appendChild(document.createTextNode((request.isDemandNonRepudiationReceipt()) ? "yes" : "no"));
	}
}
