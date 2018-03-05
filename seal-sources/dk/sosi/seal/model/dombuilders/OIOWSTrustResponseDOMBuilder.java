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
 * $HeadURL$
 * $Id$
 */

package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class OIOWSTrustResponseDOMBuilder<T extends OIOWSTrustResponseDOMBuilder> extends OIOWSTrustDOMBuilder {

    private String context;
    private String faultCode;
    private String faultActor;
    private String faultString;
    protected boolean isFault;
    private String relatesTo;

    /**
     * <b>Mandatory</b>: Set the context of the identity token.<br />
     * Example:
     *
     * <pre>
     *  &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *      <&lt;wst:RequestSecurityTokenResponse Context="urn:uuid:00000"&gt;
     *      ...
     *  &lt;/wst:RequestSecurityTokenResponseCollection&gt;
     * </pre>
     *
     * @param context
     *            The context.
     * @return The <code>OIOWSTrustResponseDOMBuilder</code> instance.
     */
    public T setContext(String context) {
        this.context = context;
        return (T) this;
    }

    /**
     * Set the code uniquely identifying the fault type.<br />
     * <br />
     * <b>Mandatory</b>: This field is mandatory for fault messages.<br />
     * The builder automatically changes into fault mode if this attribute is set.<br />
     * When in fault mode, all non fault attributes will be ignored.<br />
     *
     * <pre>
     *   &lt;soap:Body&gt;
     *     &lt;soap:Fault&gt;
     *       &lt;faultcode&gt;wst:FailedAuthentication&lt;/faultcode&gt;
     *       ...
     *     &lt;/soap:Fault&gt;
     *   &lt;/soap:Body&gt;
     * </pre>
     *
     * @param faultCode
     *            The fault code.
     * @return The <code>OIOWSTrustResponseDOMBuilder</code> instance.
     */
    public T setFaultCode(String faultCode) {
        this.faultCode = faultCode;
        this.isFault = true;
        return (T) this;
    }

    /**
     * Set the identity of the system reporting the fault.<br />
     * <br />
     * <b>Mandatory</b>: This field is mandatory for fault messages.<br />
     * The builder automatically changes into fault mode if this attribute is set.<br />
     * When in fault mode, all non fault attributes will be ignored.<br />
     *
     * <pre>
     *   &lt;soap:Body&gt;
     *     &lt;soap:Fault&gt;
     *       ...
     *       &lt;faultactor&gt;http://sosi.dk/sts&lt;/faultactor&gt;
     *     &lt;/soap:Fault&gt;
     *   &lt;/soap:Body&gt;
     * </pre>
     *
     * @param faultActor
     *            Id of the system reporting the fault.
     * @return The <code>OIOWSTrustResponseDOMBuilder</code> instance.
     */
    public T setFaultActor(String faultActor) {
        this.faultActor = faultActor;
        this.isFault = true;
        return (T) this;
    }

    /**
     * Set the identity of the system reporting the fault.<br />
     * <br />
     * <b>Mandatory</b>: This field is mandatory for fault messages.<br />
     * The builder automatically changes into fault mode if this attribute is set.<br />
     * When in fault mode, all non fault attributes will be ignored.<br />
     *
     * <pre>
     *   &lt;soap:Body&gt;
     *     &lt;soap:Fault&gt;
     *       ...
     *       &lt;faultactor&gt;http://sosi.dk/sts&lt;/faultactor&gt;
     *     &lt;/soap:Fault&gt;
     *   &lt;/soap:Body&gt;
     * </pre>
     *
     * @param faultFactor
     *            Id of the system reporting the fault.
     * @return The <code>OIOWSTrustResponseDOMBuilder</code> instance.
     *
     * @deprecated use {@link #setFaultActor(String)} instead
     */
    @Deprecated
    public T setFaultFactor(String faultFactor) {
        return setFaultActor(faultFactor);
    }

    /**
     * Set a text message describing the cause of the fault.<br />
     * <br />
     * <b>Mandatory</b>: This field is mandatory for fault messages.<br />
     * The builder automatically changes into fault mode if this attribute is set.<br />
     * When in fault mode, all non fault attributes will be ignored.<br />
     *
     * <pre>
     *   &lt;soap:Body&gt;
     *     &lt;soap:Fault&gt;
     *       ...
     *       &lt;faultstring&gt;Authentication failed: Token in request signed by untrusted party&lt;/faultstring&gt;
     *       ...
     *     &lt;/soap:Fault&gt;
     *   &lt;/soap:Body&gt;
     * </pre>
     *
     * @param faultString
     *            Text message describing the fault.
     * @return The <code>OIOWSTrustResponseDOMBuilder</code> instance.
     */
    public T setFaultString(String faultString) {
        this.faultString = faultString;
        this.isFault = true;
        return (T) this;
    }

    /**
     * <b>Mandatory</b>: Set the <code>RelatesTo</code> message id.<br />
     * Example:
     *
     * <pre>
     *  &lt;soap:Header&gt;
     *      ...
     *      &lt;wsa:RelatesTo&gt;urn:uuid:99999999-0000-0000&lt;/wsa:RelatesTo&gt;
     *  &lt;/soap:Header&gt;
     * </pre>
     *
     * @param relatesTo
     *            The message id of the request message.
     * @return The <code>OIOWSTrustResponseDOMBuilder</code> instance.
     */
    public T setRelatesTo(String relatesTo) {
        this.relatesTo = relatesTo;
        return (T) this;
    }

    @Override
    protected final void addBodyContent(Document doc, Element body) {
        if(isFault) {
            appendFaultBody(doc, body);
        } else {
            appendNormalBody(doc, body);
        }
    }

    @Override
    protected void addExtraHeaders(Document doc, Element header) {
        Element relatesToElm = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.RELATES_TO_PREFIXED);
        relatesToElm.setTextContent(relatesTo);
        header.appendChild(relatesToElm);
    }

    @Override
    protected void addExtraNamespaceDeclarations(Element envelope) {
        addNS(envelope, NameSpaces.NS_WSU, NameSpaces.WSU_SCHEMA);
    }

    @Override
    protected void validateBeforeBuild() {
        validate("relatesTo", relatesTo);
        if(isFault) {
            validate("faultCode", faultCode);
            validate("faultActor", faultActor);
            validate("faultString", faultString);
        } else {
            validate("context", context);
        }
    }

    protected abstract String getAudienceRestriction();

    protected abstract Element getIssuedTokenDOMElement();

    protected abstract Date getIssuedTokenNotBefore();

    protected abstract Date getIssuedTokenNotOnOrAfter();

    private void appendFaultBody(Document doc, Element body) {
        Element faultElm = doc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.FAULT_PREFIXED);

        Element faultCodeElm = doc.createElement("faultcode");
        faultCodeElm.setTextContent(faultCode);
        faultElm.appendChild(faultCodeElm);

        Element faultStringElm = doc.createElement("faultstring");
        faultStringElm.setTextContent(faultString);
        faultElm.appendChild(faultStringElm);

        Element faultActorElm = doc.createElement("faultactor");
        faultActorElm.setTextContent(faultActor);
        faultElm.appendChild(faultActorElm);

        body.appendChild(faultElm);
    }

    protected void appendNormalBody(Document doc, Element body) {
        Element requestSecurityTokenResponseCollectionElm = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.REQUEST_SECURITY_TOKEN_RESPONSE_COLLECTION_PREFIXED);
        body.appendChild(requestSecurityTokenResponseCollectionElm);

        // Append RequestSecurityTokenResponse
        Element requestSecurityTokenResponseElm = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.REQUEST_SECURITY_TOKEN_RESPONSE_PREFIXED);
        requestSecurityTokenResponseElm.setAttributeNS(null, WSTrustAttributes.CONTEXT, context);
        requestSecurityTokenResponseCollectionElm.appendChild(requestSecurityTokenResponseElm);

        // Append TokenType
        Element tokenTypeElm = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.TOKEN_TYPE_PREFIXED);
        tokenTypeElm.setTextContent(WSSEValues.SAML_TOKEN_TYPE);
        requestSecurityTokenResponseElm.appendChild(tokenTypeElm);

        // Append security token
        Element requestedSecurityTokenElm = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.REQUEST_SECURITY_TOKEN_PREFIXED);
        Element issuedTokenElm = (Element) doc.importNode(getIssuedTokenDOMElement(), true);
        requestedSecurityTokenElm.appendChild(issuedTokenElm);
        requestSecurityTokenResponseElm.appendChild(requestedSecurityTokenElm);

        // Append AppliesTo
        Element appliesToElm = doc.createElementNS(NameSpaces.WSP_SCHEMA, WSPTags.APPLIES_TO_PREFIXED);
        Element endpointReferenceElm = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ENDPOINT_REFERENCE_PREFIXED);
        Element addressElm = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ADDRESS_PREFIXED);
        addressElm.setTextContent(getAudienceRestriction());
        endpointReferenceElm.appendChild(addressElm);
        appliesToElm.appendChild(endpointReferenceElm);
        requestSecurityTokenResponseElm.appendChild(appliesToElm);

        // Append lifetime
        Element lifetimeElm = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.LIFETIME_PREFIXED);
        Element createdElm = doc.createElementNS(NameSpaces.WSU_SCHEMA, WSUTags.CREATED_PREFIXED);
        createdElm.setTextContent(XmlUtil.getDateFormat(true).format(getIssuedTokenNotBefore()));
        lifetimeElm.appendChild(createdElm);
        Element expiresElm = doc.createElementNS(NameSpaces.WSU_SCHEMA, WSUTags.EXPIRES_PREFIXED);
        expiresElm.setTextContent(XmlUtil.getDateFormat(true).format(getIssuedTokenNotOnOrAfter()));
        lifetimeElm.appendChild(expiresElm);
        requestSecurityTokenResponseElm.appendChild(lifetimeElm);

        appendAdditionalToResponseCollection(doc, requestSecurityTokenResponseCollectionElm);
    }

    protected void appendAdditionalToResponseCollection(Document doc, Element requestSecurityTokenResponseCollectionElm) {
    }
}
