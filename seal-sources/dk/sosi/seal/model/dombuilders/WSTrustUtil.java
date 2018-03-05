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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/WSTrustUtil.java $
 * $Id: WSTrustUtil.java 20767 2014-12-10 15:12:04Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.constants.NameSpaces;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Utility method for handling WSTrust.
 *
 * @author Peter Buus
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class WSTrustUtil { // NOPMD

	public static final String VERSION = "2.0";
	private static final String urn = "urn:oasis:names:tc:SAML:2.0:assertion:";
	private static final String Issue = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
	private static final String Valid = "http://schemas.xmlsoap.org/ws/2005/02/trust/status/valid";

	public Element createSecurityTokenRequest(Document document, IDCard idCard) {

		if (idCard == null) throw new ModelException("No IDCard present in SecurityTokenRequest");

		Element elmWsTrust = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":RequestSecurityToken");
		elmWsTrust.setAttributeNS(null, "Context", "www.sosi.dk");

		Element elmRequestType = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":TokenType");
		elmRequestType.appendChild(document.createTextNode(urn));
		elmWsTrust.appendChild(elmRequestType);

		Element elmTokenType = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":RequestType");
		elmTokenType.appendChild(document.createTextNode(Issue));
		elmWsTrust.appendChild(elmTokenType);


		Element elmClaims = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":Claims");
		//TODO fixme sosifactory instead of null
        elmClaims.appendChild(idCard.serialize2DOMDocument(null, document));
		elmWsTrust.appendChild(elmClaims);

		Element elmIssuer = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":Issuer");
		Element elmAddress = document.createElementNS(NameSpaces.WSA_SCHEMA, NameSpaces.NS_WSA + ":Address");
		elmAddress.appendChild(document.createTextNode(idCard.getIssuer()));
		elmIssuer.appendChild(elmAddress);
		elmWsTrust.appendChild(elmIssuer);

		return elmWsTrust;

	}

	public Element createSecurityTokenResponse(Document document, IDCard idCard) {

		if (idCard == null) throw new ModelException("No idCard present in SecurityTokenResponse");

		Element elmWsTrust = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":RequestSecurityTokenResponse");
		elmWsTrust.setAttributeNS(null, "Context", "www.sosi.dk");

		Element elmTokenType = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":TokenType");
		elmTokenType.appendChild(document.createTextNode(urn));
		elmWsTrust.appendChild(elmTokenType);

		Element elmRequestedSecurityTokens = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":RequestedSecurityToken");
        //TODO fixme sosifactory instead of null
		elmRequestedSecurityTokens.appendChild(idCard.serialize2DOMDocument(null,document));
		elmWsTrust.appendChild(elmRequestedSecurityTokens);

		Element elmStatus = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":Status");
		Element elmStatusCode = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":Code");
		elmStatusCode.appendChild(document.createTextNode(Valid));
		elmStatus.appendChild(elmStatusCode);
		elmWsTrust.appendChild(elmStatus);

		Element elmIssuer = document.createElementNS(NameSpaces.WST_SCHEMA, NameSpaces.NS_WST + ":Issuer");
		Element elmAddress = document.createElementNS(NameSpaces.WSA_SCHEMA, NameSpaces.NS_WSA + ":Address");
		elmAddress.appendChild(document.createTextNode(idCard.getIssuer()));
		elmIssuer.appendChild(elmAddress);
		elmWsTrust.appendChild(elmIssuer);

		return elmWsTrust;

	}

}
