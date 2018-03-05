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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/model/dombuilders/MessageDOMBuilder.java $
 * $Id: MessageDOMBuilder.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.vault.renewal.model.dombuilders;

import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.model.dombuilders.DOMBuilderException;
import dk.sosi.seal.vault.renewal.model.Argument;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Class for building DOM objects from renewal messages.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public abstract class MessageDOMBuilder { //NOPMD
	protected Document document;
	protected Element body;
	
    protected void addNameSpaceAttribute(String name, String value) {
        Element documentElement = document.getDocumentElement();
        addNameSpaceAttributeToElement(name, value, documentElement);
    }

	protected void addNameSpaceAttributeToElement(String name, String value, Element documentElement) {
		if(documentElement.getAttributeNS(NameSpaces.XMLNS_SCHEMA,name)==null || documentElement.getAttributeNS(NameSpaces.XMLNS_SCHEMA,name).equals("")) {
        	documentElement.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS+":"+name, value);
        }
	}

    /**
     * Initializes a SOAP message with elements that are common to all
     * renewal messages.
     */
    protected void initializeSOAP(boolean setupHeader) {
    	Element root = document.getDocumentElement();
        if (root == null) {
            root = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
            document.appendChild(root);
        }

        addNameSpaceAttribute(NameSpaces.NS_SOAP, NameSpaces.SOAP_SCHEMA);
        addNameSpaceAttribute(NameSpaces.NS_XSI, NameSpaces.XMLSCHEMAINSTANCE_SCHEMA);
        addNameSpaceAttribute(NameSpaces.NS_XSD, NameSpaces.XSD_SCHEMA);

		//Add empty header element
		NodeList nodes;
        
		if (setupHeader) {
	        nodes = root.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED);
	        if (nodes.getLength() == 0) {
				Element header = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_PREFIXED);
				root.appendChild(header);
	        } else if(nodes.getLength() == 1) { 
	        	//OK, one header element is expected
	        } else { //NOPMD
	        	throw new DOMBuilderException("Too many soap:Header elements in document!", null);
	        }

		}		

        nodes = root.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_UNPREFIXED);
        if (nodes.getLength() == 0) {
            body = document.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_PREFIXED);
            root.appendChild(body);
        } else if(nodes.getLength() == 1) {
        	body = (Element)nodes.item(0);
        } else {
        	throw new DOMBuilderException("Too many soap:Body elements in document!", null);
        }
    }
    
    /**
     * Adds a method argument to the DOM representation of the message.
     * @param method
     * @param argument
     */
	protected void addMethodArgument(Element method, Argument argument) {
		Element argumentElement = document.createElement(argument.getName());
		
		if(argument.getType().equals(String.class)) {
			argumentElement.setAttributeNS(NameSpaces.XMLSCHEMAINSTANCE_SCHEMA, Constants.XSI_TYPE, Constants.XSD_STRING);
			argumentElement.appendChild(document.createTextNode((String) argument.getValue()));
		} else if(argument.getType().equals(byte[].class)) {
			argumentElement.setAttributeNS(NameSpaces.XMLSCHEMAINSTANCE_SCHEMA, Constants.XSI_TYPE, Constants.XSD_BASE64BINARY);
			argumentElement.appendChild(document.createTextNode(XmlUtil.toBase64((byte[]) argument.getValue())));
		} else if(argument.getType().equals(Integer.class) || argument.getType().equals(Integer.TYPE)) {
			argumentElement.setAttributeNS(NameSpaces.XMLSCHEMAINSTANCE_SCHEMA, Constants.XSI_TYPE, Constants.XSD_INT);
			argumentElement.appendChild(document.createTextNode(argument.getValue().toString()));
		} else {
			throw new DOMBuilderException("Unsupported argument type: " + argument.getType().getName(), null);
		}
		
		method.appendChild(argumentElement);
		
	}


	
}
