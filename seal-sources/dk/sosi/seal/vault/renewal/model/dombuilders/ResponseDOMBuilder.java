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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/model/dombuilders/ResponseDOMBuilder.java $
 * $Id: ResponseDOMBuilder.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.model.dombuilders;

import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.dombuilders.DOMBuilderException;
import dk.sosi.seal.vault.renewal.model.Argument;
import dk.sosi.seal.vault.renewal.model.Response;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Class for building DOM objects from renewal response model objects.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class ResponseDOMBuilder extends MessageDOMBuilder {

	private Response response;

	/**
	 * Construct a DOM builder
	 * 
	 * @param document
	 * 		document into which the DOM representation of the response should be built
	 * @param response
	 * 		the response model object to build a DOM representation of
	 */
	public ResponseDOMBuilder(Document document, Response response) {
		super();
		this.document = document;
		this.response = response;
	}

	/**
	 * Build a DOM representation of the request request.
	 * @return The generated <code>Document</code>.
	 */
	public Document buildDocument() {
		initializeSOAP(true);

		// Add method element
		Element messageElement = document.createElementNS(Constants.LOCAL_SCHEMA,
				Constants.NS_LOCAL + ":" + response.messageName());
		messageElement.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":"
				+ Constants.NS_LOCAL, Constants.LOCAL_SCHEMA);
		messageElement.setAttributeNS(NameSpaces.SOAP_SCHEMA, Constants.SOAP_ENCODINGSTYLE, Constants.SOAP_ENCODINGSTYLE_URI);

		Element result = document.createElement("result");
		result.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:resultns", "java:" + response.getClass().getPackage().getName());
		
		String[] subs = response.getClass().getName().split("\\.");
		result.setAttributeNS(NameSpaces.XMLSCHEMAINSTANCE_SCHEMA, Constants.XSI_TYPE, "resultns:" + subs[subs.length - 1]);

		Method[] methods = response.getClass().getDeclaredMethods();

		for (int i = 0; i < methods.length; i++) {
			Method method = methods[i];
			if (method.getName().startsWith("get") && method.getParameterTypes().length == 0) {
				String name = method.getName().substring(3, 4).toLowerCase()
						+ method.getName().substring(4);
				try {
					Argument arg = new Argument(name, method.getReturnType(), method.invoke(response, new Object[0]));
					addMethodArgument(result, arg);
				} catch (IllegalArgumentException e) {
					throw new DOMBuilderException("Failed to build document", e);
				} catch (IllegalAccessException e) {
					throw new DOMBuilderException("Failed to build document", e);
				} catch (InvocationTargetException e) {
					throw new DOMBuilderException("Failed to build document", e);
				}
			}
		}

		messageElement.appendChild(result);

		body.appendChild(messageElement);

		return document;
	}
}
