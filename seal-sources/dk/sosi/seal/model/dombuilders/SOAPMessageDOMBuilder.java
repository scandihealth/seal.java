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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/SOAPMessageDOMBuilder.java $
 * $Id: SOAPMessageDOMBuilder.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.Message;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Abstract builder class for SOSI SOAP messages.
 * 
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
abstract class SOAPMessageDOMBuilder {

	private final Message message;
    private final SignatureProvider signatureProvider;

    private Document document;
    private Element header;
	private Element body;

    /**
     * Constructs the DOM builder for a SOAP message.
     *
     * @param document
     *            the enclosing DOM document
     * @param message
     *            The <code>Message</code> model element
     * @param vault
     *            The credential valt with system signature
     */
    @Deprecated
    protected SOAPMessageDOMBuilder(Document document, Message message, CredentialVault vault) {

        super();
        this.document = document;
        this.message = message;
        this.signatureProvider = SignatureProviderFactory.fromCredentialVault(vault);
        initializeSOAP();
    }
	/**
	 * Constructs the DOM builder for a SOAP message.
	 *  @param document
	 *            the enclosing DOM document
	 * @param message
	 *            The <code>Message</code> model element
     * @param signatureProvider
     */
	protected SOAPMessageDOMBuilder(Document document, Message message, SignatureProvider signatureProvider) {

		super();
		this.document = document;
		this.message = message;
        this.signatureProvider = signatureProvider;
        initializeSOAP();
	}

	// ===============================
	// Protected methods
	// ===============================

	/**
	 * Initializes a SOAP message (Header+Body) with elements that are common to
	 * all SOSI messages.
	 */
	protected void initializeSOAP() {

		Element root = document.getDocumentElement();
		if (root == null) {
			root = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
			document.appendChild(root);
		}

		Map<String, String> nameSpaces;
		if(message.isFault()) nameSpaces = NameSpaces.SOSI_FAULT_NAMESPACES;
		else nameSpaces = NameSpaces.SOSI_NAMESPACES;
		for (Iterator<String> iter = nameSpaces.keySet().iterator(); iter.hasNext();) {
			String key = iter.next();
			addNameSpaceAttribute(key, nameSpaces.get(key));
		}

        String sealMsgVersion = SOSIFactory.PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION;
        if(message.getFactory() != null) 
            sealMsgVersion = message.getFactory().getProperties().getProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, SOSIFactory.PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION);
        
        if("1.0_0".equals(sealMsgVersion)) {
            root.setAttributeNS(null, "id", "Envelope");
        } else if("1.0_1".equals(sealMsgVersion)) {
            root.setAttributeNS(NameSpaces.WSU_SCHEMA, NameSpaces.NS_WSU+":id", SOAPTags.ENVELOPE_UNPREFIXED);
        } else if("1.0_2".equals(sealMsgVersion)) {
            root.setAttributeNS(NameSpaces.WSU_SCHEMA, NameSpaces.NS_WSU+":id", SOAPTags.ENVELOPE_UNPREFIXED);
        }

		NodeList nodes = root.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED);
		if (nodes.getLength() == 0) {
			header = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_PREFIXED);
			root.appendChild(header);
		} else if (nodes.getLength() == 1) {
			header = (Element) nodes.item(0);
			NodeList children = header.getChildNodes();
			List<Node> list = new LinkedList<Node>();
			for (int i = 0; i < children.getLength(); i++) {
				list.add(children.item(0));
			}
			for (Iterator<Node> iter = list.iterator(); iter.hasNext();) {
                header.removeChild(iter.next());
			}
		} else {
			throw new DOMBuilderException("Too many soap:Header elements in document!", null);
		}

		nodes = root.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_UNPREFIXED);
		if (nodes.getLength() == 0) {
			body = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_PREFIXED);
			root.appendChild(body);
		} else if (nodes.getLength() == 1) {
			body = (Element) nodes.item(0);
		} else {
			throw new DOMBuilderException("Too many soap:Body elements in document!", null);
		}
	}

	/**
	 * Returns the Message object.
	 */
	protected Message getMessage() {

		return message;
	}

	/**
	 * Builds the DOM document for a message.
	 */
	public final Document buildDOMDocument() {
		_buildDOMDocument(document, header, body);

		// Digital signature on the IDCard - only possible when signing with
		// VOCES
		IDCard idCard = message.getIDCard();
		if (idCard != null && idCard.getAuthenticationLevel().getLevel() == AuthenticationLevel.VOCES_TRUSTED_SYSTEM.getLevel()) {
			idCard.sign(document, signatureProvider);
		}

        // Add Non SOSI Headers
        if (message.getNonSOSIHeaders() != null) {
            for (Iterator<Element> it = message.getNonSOSIHeaders().iterator(); it.hasNext();) {
                Element e = it.next();
                header.appendChild(document.importNode(e, true));
            }
        }
        
		// Body
		if (message.getBody() != null && body.getChildNodes().getLength() == 0) {
			// insert body from message if not already inserted (SecurityTokenRequestResponse)
			body.appendChild(document.importNode(message.getBody(), true));
		}

		// Other digital signatures should go here

		return document;

	}

	/**
	 * Adds a XML name space attribute to the DOM document contained in this
	 * builder.
	 * 
	 * @param name
	 *            The name of the name space.
	 * @param value
	 *            The value for the name space.
	 */
	protected void addNameSpaceAttribute(String name, String value) {

		Element documentElement = document.getDocumentElement();
		if (documentElement.getAttributeNS(NameSpaces.XMLNS_SCHEMA, name) == null
				|| documentElement.getAttributeNS(NameSpaces.XMLNS_SCHEMA, name).equals("")) {
			documentElement.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + name, value);
		}
	}

	/**
	 * Builds and returns a DOM element for a given sub class message.
	 */
	protected abstract void _buildDOMDocument(Document doc, Element headerElement, Element bodyElement);
}