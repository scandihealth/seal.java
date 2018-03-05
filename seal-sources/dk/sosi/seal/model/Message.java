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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/Message.java $
 * $Id: Message.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * The superclass for all SOSI messages.
 * 
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public abstract class Message {

    private Date creationDate = new Date();
    private IDCard idCard;

    private String messageID;
    private String flowID;
    private String dgwsVersion;

    private Element body = null;
    private List<Element> nonSOSIHeaders = null;

    // Back reference to the factory that created this instance.
    private final SOSIFactory factory;
    protected IDCardValidator validator;
    protected boolean isFault;

    Message(String dgwsVersion, String flowID, SOSIFactory factory) {
        super();
        if(!DGWSConstants.SUPPORTED_VERSIONS.contains(dgwsVersion))
            throw new ModelException("DGWS version '" + dgwsVersion + "' not supported. Supported versions are: " + DGWSConstants.SUPPORTED_VERSIONS);
        this.dgwsVersion = dgwsVersion;
        this.validator = new IDCardValidator();
        this.flowID = flowID;
        this.messageID = XmlUtil.createNonce();
        this.factory = factory;
    }

    Message(String dgwsVersion, SOSIFactory factory) {
        this(dgwsVersion, null, factory);
    }

    /**
     * Returns the content of soap:body, or <code>null</code> if none set.
     */
    public Element getBody() {
        return body;
    }

    /**
     * Sets the content of soap:body
     * 
     * @param body
     *            The content of the soap:body element
     */
    public void setBody(Element body) {
        this.body = body;
    }

    /**
     * Returns the non sosi headers of soap:header, or <code>null</code> if none set.
     */
    public List<Element> getNonSOSIHeaders() {
        return nonSOSIHeaders;
    }

    /**
     * Adds a non sosi header to soap:header
     * 
     * @param header
     */
    public void addNonSOSIHeader(Element header) {
        if(nonSOSIHeaders == null)
            nonSOSIHeaders = new ArrayList<Element>();
        nonSOSIHeaders.add(header);
    }

    /**
     * Returns the creation date+time for this message.
     */
    public Date getCreationDate() {

        return creationDate;
    }

    /**
     * Sets creation date+time for this message.
     */
    public void setCreationDate(Date date) {

        creationDate = date;
    }

    /**
     * Returns the aggregated <code>IDCard</code> instance (composition)
     * 
     * @return <code>IDCard</code> or <code>null</code> if the relation is uninitialized.
     */
    public IDCard getIDCard() {

        return idCard;
    }

    /**
     * Associates a (new) <code>IDCard</code> instance to this message.
     * 
     * @param newIDCard
     *            the new <code>IDCard</code> to associate.
     */
    public void setIDCard(IDCard newIDCard) {
        if(!isFault())
            validator.validateIDCard(newIDCard);
        idCard = newIDCard;
    }

    /**
     * Returns a globally unique ID for this message. This attribute is also a nonce that is globally unique (with high propability) within the last 5 minutes window.
     */
    public String getMessageID() {

        return messageID;
    }

    /**
     * Sets a globally unique ID for this message.
     */
    public void setMessageID(String msgID) {

        messageID = msgID;
    }

    /**
     * Returns the unique flow ID for this message. This attribute is used when sending correlated messages (e.g. messages in the same message "flow"), and can be used by service providers and consumers to discover messages that are correlated.
     * <p/>
     * Many messages may share the same flow ID, whereas the <code>MessageID</code> is unique for this one message. The <code>flowID</code> may be <code>null</code> if flows are not used/supported. In this case, the <code>flowID</code> will have the same value as the <code>messageID</code>.
     */
    public String getFlowID() {

        return flowID;
    }

    /**
     * Sets a unique flow ID for this message.
     */
    public void setFlowID(String flowID) {

        this.flowID = flowID;
    }

    // ====================================
    // DOM generation stuff
    // ====================================

    /**
     * Returns a DOM representation of this <code>Message</code>. The DOM is essentially a SOAP envelope with a SOSI compliant Header and an empty body. The body must be set afterwards.
     * <p/>
     * The DOM representation is regenerated on demand if the message (or composed model elements) are "dirty".
     */
    public Document serialize2DOMDocument(Document doc) {
        SignatureProvider signatureProvider = null;
        if(factory != null)
            signatureProvider = factory.getSignatureProvider();
        regenerateDOM(doc, signatureProvider);
        return doc;
    }

    public Document serialize2DOMDocument() {
        Document doc = XmlUtil.createEmptyDocument();
        serialize2DOMDocument(doc);
        return doc;
    }

    /**
     * Regenerates the DOM representation (subclasses).
     */
    protected abstract Document regenerateDOM(Document document, SignatureProvider signatureProvider);

    // ====================================
    // Overridden methods
    // ====================================

    /**
     * @see Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj) {

        return obj == this || obj != null && obj.getClass() == getClass() && obj.hashCode() == hashCode() && getDGWSVersion().equals(((Message)obj).getDGWSVersion()) && (getCreationDate().getTime() / 1000 == ((Message)obj).getCreationDate().getTime() / 1000)
                && ((getIDCard() == null && ((Message)obj).getIDCard() == null) || (getIDCard() != null && getIDCard().equals(((Message)obj).getIDCard()))) && ((getFlowID() == null && ((Message)obj).getFlowID() == null) || (getFlowID() != null && getFlowID().equals(((Message)obj).getFlowID())));
    }

    /**
     * @see Object#hashCode()
     */
    public int hashCode() {

        return messageID.hashCode();
    }

    /**
     * Returns the SOSIFactory.
     */
    public SOSIFactory getFactory() {

        return factory;
    }

    public boolean isFault() {

        return isFault;
    }

    public String getDGWSVersion() {
        return dgwsVersion;
    }

    public void setDGWSVersion(String dgwsVersion) {
        this.dgwsVersion = dgwsVersion;
    }
}
