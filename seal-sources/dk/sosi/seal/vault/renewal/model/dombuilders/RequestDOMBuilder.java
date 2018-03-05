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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/model/dombuilders/RequestDOMBuilder.java $
 * $Id: RequestDOMBuilder.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.model.dombuilders;

import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.vault.renewal.model.Argument;
import dk.sosi.seal.vault.renewal.model.Request;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Class for building DOM objects from renewal request model objects.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class RequestDOMBuilder extends MessageDOMBuilder {
	
	private final Request request;
	
	/**
	 * Construct a DOM builder
	 * 
	 * @param document
	 * 		document into which the DOM representation of the request should be built
	 * @param request
	 * 		the request model object to build a DOM representation of
	 */
	public RequestDOMBuilder(Document document, Request request) {
		super();
		this.document = document;
		this.request = request;
	}
	
   
	/**
	 * Build a DOM representation of the renewal request.
	 * @return The generated <code>Document</code>.
	 */
    public Document buildDocument() {
    	initializeSOAP(false);
    	
    	//Add method element
    	Element method = document.createElementNS(Constants.LOCAL_SCHEMA, Constants.NS_LOCAL + ":" + request.messageName());
    	method.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + Constants.NS_LOCAL, Constants.LOCAL_SCHEMA);
    	method.setAttributeNS(NameSpaces.SOAP_SCHEMA, Constants.SOAP_ENCODINGSTYLE, Constants.SOAP_ENCODINGSTYLE_URI);
    	
    	Argument[] args = request.getArguments();
    	for (int i = 0; i < args.length; i++) {
			addMethodArgument(method, args[i]);
		}
    	
    	body.appendChild(method);
    	return document;
    }





}
