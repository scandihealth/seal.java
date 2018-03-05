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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/Reply.java $
 * $Id: Reply.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.dombuilders.SAMLReplyDOMBuilder;
import dk.sosi.seal.pki.SignatureProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Collections;
import java.util.List;

/**
 * Interface for SOSI/DGWS SOAP replies.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class Reply extends Message {

	private String requestID;
	private String flowStatus;
	private String faultCode;
	private String faultString;
    private List<Element> extraFaultDetails;

	/**
	 * @param dgwsVersion
	 * 			  The DGWS version this message adheres to
	 * @param requestID
	 *            ID of the corresponding request message
	 * @param flowID
	 *            A unique flow ID for this reply message.
	 * @param flowStatus
	 *            Status for this reply message.
	 * @param factory
	 *            SOSIFactory to construct realizations of the SOSI abstractions
	 *            in the seal component.
	 */
	public Reply(String dgwsVersion, String requestID, String flowID, String flowStatus, SOSIFactory factory) {

		super(dgwsVersion, flowID, factory);
		this.requestID = requestID;
		this.flowStatus = flowStatus;
		this.isFault = false;
	}

	public Reply(String dgwsVersion, String requestID, String flowID, String faultCode, String faultString, SOSIFactory factory) {

        this(dgwsVersion, requestID, flowID, faultCode, faultString, factory, null);
	}

    public Reply(String dgwsVersion, String requestID, String flowID, String faultCode, String faultString, SOSIFactory factory, List<Element> extraFaultDetails) {

        super(dgwsVersion, flowID, factory);
        this.requestID = requestID;
        this.isFault = true;
        this.faultCode = faultCode;
        this.faultString = faultString;
        this.extraFaultDetails = extraFaultDetails != null ? extraFaultDetails : Collections.EMPTY_LIST;
    }

    /**
	 * Returns the ID of the corresponding request message. This is a read-only
	 * attribute.
	 */
	public String getRequestID() {

		return requestID;
	}

	/**
	 * Returns the status for this reply message.
	 */
	public String getFlowStatus() {

		if (isFault()) {
			// TODO: is this true (JRI)?
			throw new ModelException("The reply represents a Fault. No FlowStatus available");
		}
		return flowStatus;
	}

	/**
	 * Sets the status for this reply message.
	 */
	public void setFlowStatus(String flowStatus) {

		this.flowStatus = flowStatus;
	}

	/**
	 * Sets the ID of the corresponding request message.
	 */
	public void setRequestID(String reqID) {

		requestID = reqID;
	}

    public List<Element> getExtraFaultDetails() {
        if (!isFault()) {
            throw new ModelException("The reply is not a Fault. No extra fault details available");
        }
        return extraFaultDetails;
    }

	public boolean isFault() {

		return isFault;
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
		Reply reply = (Reply) obj;
		if (!getRequestID().equals(reply.getRequestID()))
			return false; // NOPMD
		if (isFault()) {
			if (!getFaultCode().equals(reply.getFaultCode()))
				return false; // NOPMD
			if (!getFaultString().equals(reply.getFaultString()))
				return false; // NOPMD
		} else {
			if (!getFlowStatus().equals(reply.getFlowStatus()))
				return false; // NOPMD
		}
		return true;
	}

	/**
	 * Generates a new XML document using the given reply message.
	 */
    protected Document regenerateDOM(Document doc, SignatureProvider signatureProvider) {

		return new SAMLReplyDOMBuilder(doc, this, signatureProvider).buildDOMDocument();
	}
}
