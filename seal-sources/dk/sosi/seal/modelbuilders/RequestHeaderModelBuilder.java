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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/RequestHeaderModelBuilder.java $
 * $Id: RequestHeaderModelBuilder.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.RequestHeader;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class RequestHeaderModelBuilder{

	private final SOSIFactory factory;

	public RequestHeaderModelBuilder(SOSIFactory factory) {
		this.factory = factory;
	}

	public RequestHeader buildModel(Document headerDoc) throws ModelBuildException {
		Request request = buildRequest(headerDoc);
		return new RequestHeader(request.getDGWSVersion(), request.getCreationDate(), request.getIDCard(),
				request.getMessageID(), request.getFlowID(), headerDoc, request.isDemandNonRepudiationReceipt());
	}

	private Request buildRequest(Document headerDoc) throws ModelBuildException {
		Document doc = XmlUtil.createEmptyDocument();
		Element envelope = doc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
		doc.appendChild(envelope);
		Node header = doc.importNode(headerDoc.getDocumentElement(), true);
		envelope.appendChild(header);
		return new RequestModelBuilder(factory).buildModel(doc);
	}

}
