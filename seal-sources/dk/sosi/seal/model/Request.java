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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/Request.java $
 * $Id: Request.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.dombuilders.SAMLRequestDOMBuilder;
import dk.sosi.seal.pki.SignatureProvider;
import org.w3c.dom.Document;

/**
 * Model class for SOSI requests.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class Request extends Message {

	private final boolean demandNR;

	/**
	 * Constructs a <code>Request</code> model element
	 * @param dgwsVersion
	 * 			  The DGWS version this message adheres to
	 * @param demandNR
	 *            if <code>true</code> the response for this request should be
	 *            signed by the service provider
	 * @param flowID
	 *            an optional ID for a flow (session, transaction) of messages.
	 * @param factory
	 *            the factory that is creating this request
	 */
	public Request(String dgwsVersion, boolean demandNR, String flowID, SOSIFactory factory) {

		super(dgwsVersion, flowID, factory);
		this.demandNR = demandNR;
	}

	/**
	 * If <code>true</code> the service consumer is demanding a
	 * non-repudiation receipt (digital signature) on the reply for this
	 * request.
	 */
	public boolean isDemandNonRepudiationReceipt() {

		return demandNR;
	}

	// ================================
	// Overridden methods
	// ================================

	/**
	 * Generates a new XML document using the given request message.
	 */
    protected Document regenerateDOM(Document doc, SignatureProvider signatureProvider) {

		return new SAMLRequestDOMBuilder(doc, this, signatureProvider).buildDOMDocument();
	}

	public boolean equals(Object obj) { // NOPMD

		if (!super.equals(obj) || obj.getClass() != getClass())
			return false; // NOPMD
		Request request = (Request) obj;
		return isDemandNonRepudiationReceipt() == request.isDemandNonRepudiationReceipt();
	}
}
