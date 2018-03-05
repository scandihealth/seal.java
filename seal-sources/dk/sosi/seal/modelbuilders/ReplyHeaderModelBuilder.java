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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/ReplyHeaderModelBuilder.java $
 * $Id: ReplyHeaderModelBuilder.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.Reply;
import dk.sosi.seal.model.ReplyHeader;
import dk.sosi.seal.model.constants.MedComTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class ReplyHeaderModelBuilder {

	private final SOSIFactory factory;

	public ReplyHeaderModelBuilder(SOSIFactory factory) {
		this.factory = factory;
	}

	public ReplyHeader buildModel(Document headerDoc) throws ModelBuildException {
		checkForFault(headerDoc);
		Reply reply = buildReply(headerDoc);
		return new ReplyHeader(reply.getDGWSVersion(), reply.getCreationDate(), reply.getIDCard(), reply.getMessageID(), reply.getFlowID(), reply
				.getRequestID(), reply.getFlowStatus(), headerDoc);
	}

	private void checkForFault(Document headerDoc) throws ModelBuildException {
		NodeList flowStatusList = headerDoc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.FLOW_STATUS);
		if (flowStatusList.getLength() == 0) {
			throw new ModelBuildException("No " + MedComTags.FLOW_STATUS_PREFIXED + " present in header. This header probably belonged to an error reply.");
		}
	}

	private Reply buildReply(Document headerDoc) throws ModelBuildException {
		Document doc = XmlUtil.createEmptyDocument();
		Element envelope = doc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
		doc.appendChild(envelope);
		Node header = doc.importNode(headerDoc.getDocumentElement(), true);
		envelope.appendChild(header);
		return new ReplyModelBuilder(factory).buildModel(doc);
	}

}
