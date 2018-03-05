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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/xml/AxisUtil.java $
 * $Id: AxisUtil.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.xml;

import dk.sosi.seal.model.Message;
import dk.sosi.seal.model.constants.NameSpaces;
import org.apache.axis.message.SOAPEnvelope;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.soap.SOAPException;
import java.util.Iterator;
import java.util.Map;

/**
 * Util for Axis integration
 * 
 * @author Simon
 * @author $Author: chg@lakeside.dk $
 * @since 1.5
 */
@Deprecated
public class AxisUtil {

	/**
	 * Adds the soapenv:Header parts of the Document to SOAPEnvelope
	 * 
	 * @param env
	 * @param doc
	 * @throws SOAPException
	 */
	public static void addHeadersToSOAPEnvelope(SOAPEnvelope env, Document doc, boolean isFaultMessage) throws SOAPException {
		// Make sure that all namespaces are present in the axis response
		Map<String, String> namespaces;
		
		if(isFaultMessage)
			namespaces = NameSpaces.SOSI_FAULT_NAMESPACES;
		else
			namespaces = NameSpaces.SOSI_NAMESPACES;
		
		Iterator<String> it = namespaces.keySet().iterator();
		while (it.hasNext()) {
			String namespace = it.next();
			env.addNamespaceDeclaration(namespace, namespaces.get(namespace));
		}
		env.addAttribute(env.createName("id"), "Envelope");
		
		// Now transfer the generated header elements back to the axis context
		Element docHeader = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA,"Header").item(0);
		DOMHeaderElement headerElement = new DOMHeaderElement(docHeader);
		env.addHeader(headerElement);
	}
	
	/**
	 * Adds the soapenv:Body part of the Document to SOAPEnvelope
	 * 
	 * @param env
	 * @param doc
	 */
	public static void addBodyToSOAPEnvelope(SOAPEnvelope env, Document doc) {
		Element docBody = (Element) doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Body").item(0);
		DOMBodyElement bodyElement = new DOMBodyElement(docBody);

		env.addBodyElement(bodyElement);
	}

	/**
	 * Adds the soapenv:Header parts of the Message to SOAPEnvelope
	 * 
	 * If fault message only needed namespaces are added
	 * 
	 * @param req
	 * @param request
	 * @throws SOAPException
	 */
	public static void addMessageToSOAPEnvelope(SOAPEnvelope req, Message request) throws SOAPException {
		Document doc = request.serialize2DOMDocument();
		addHeadersToSOAPEnvelope(req, doc, request.isFault());
	}
}
