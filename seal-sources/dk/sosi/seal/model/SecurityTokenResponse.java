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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/SecurityTokenResponse.java $
 * $Id: SecurityTokenResponse.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.dombuilders.SecurityTokenResponseDOMBuilder;
import dk.sosi.seal.pki.SignatureProvider;
import org.w3c.dom.Document;

/**
 * Model class for SOSI SecurityToken reply.
 *
 * @author Peter Buus
 * @since 1.0
 */
public class
        SecurityTokenResponse extends Message {

	private String faultCode;
	private String faultString;
	private String faultActor;

	/**
	 * @param dgwsVersion
	 * 			  The DGWS version this message adheres to
	 * @param inResponseToID
	 *            ID of the corresponding request message
	 * @param factory
	 *            SOSIFactory to construct realizations of the SOSI abstractions
	 *            in the seal component.
	 */
	public SecurityTokenResponse(String dgwsVersion,String inResponseToID, SOSIFactory factory) {

		super(dgwsVersion, factory);
		setMessageID(inResponseToID);
		this.isFault = false;
	}

	/**
	 * Creates a new STS error response.
	 *
	 *            ID of the corresponding request message
	 * @param dgwsVersion
	 * 			  The DGWS version this message adheres to
	 * @param factory
	 *            SOSIFactory to construct realizations of the SOSI abstractions
	 *            in the seal component.
	 */
	public SecurityTokenResponse(String dgwsVersion,String messageID, String faultCode, String faultString, String faultActor, SOSIFactory factory) {
		super(dgwsVersion, factory);
		setMessageID(messageID);
		this.isFault = true;
		this.faultCode = faultCode;
		this.faultString = faultString;
		this.faultActor = faultActor;
	}

	public String getFaultCode() {
		if (!isFault()) {
			throw new ModelException("The reply is not a Fault. No FaultCode available");
		}
		return (faultCode==null)?"":faultCode;
	}

	public String getFaultString() {
		if (!isFault()) {
			throw new ModelException("The reply is not a Fault. No FaultString available");
		}
		return (faultString==null)?"":faultString;
	}

	public String getFaultActor() {
		if (!isFault()) {
			throw new ModelException("The reply is not a Fault. No FaultString available");
		}
		return( faultActor==null)?"":faultActor;
	}

	public void setIDCard(IDCard idCard) {
		if(isFault())
			throw new ModelException("IDCards cannot be attached to error replies");
		super.setIDCard(idCard);
	}

	/**
	 * Overrides Message.equals(). hashCode() is overwritten in superclass.
	 */
	public boolean equals(Object obj) { // NOPMD

		if (!super.equals(obj) || obj.getClass() != getClass())
			return false; // NOPMD
		SecurityTokenResponse reply = (SecurityTokenResponse) obj;
		if (isFault()) {
			if (!getFaultCode().equals(reply.getFaultCode()))
				return false; // NOPMD
			if (!getFaultString().equals(reply.getFaultString()))
				return false; // NOPMD
			if (!getFaultActor().equals(reply.getFaultActor()))
				return false; // NOPMD
		}
		return true;
	}

	public void setFlowID(String flowID) throws ModelException {
		throw new ModelException("Not applicable for SecurityTokenResponse");
	}

	/**
	 * Generates a new XML document using the given reply message.
	 */
	protected Document regenerateDOM(Document doc, SignatureProvider signatureProvider) {
		return new SecurityTokenResponseDOMBuilder(doc, this, signatureProvider).buildDOMDocument();
	}
}
