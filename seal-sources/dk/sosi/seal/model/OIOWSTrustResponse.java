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

package dk.sosi.seal.model;

import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.pki.Federation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOWSTrustResponse extends OIOWSTrustMessage {

    private transient Boolean fault = null;

    public OIOWSTrustResponse(Document doc) {
        super(doc);
    }

    /**
     * Retrieve the context attribute of the <i>wst:RequestSecurityTokenResponse</i> tag.
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse Context=&quot;urn:uuid:00000&quot;&gt;
     *              ...
     *          &lt;/wst:RequestSecurityTokenResponse&gt;
     *      &lt;/wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;/soap:Body&gt;
     * </pre>
     *
     * @return The context value.
     */
    public String getContext() {
        if(isFault()) {
            return null;
        }
        return safeGetAttribute(WSTrustAttributes.CONTEXT, SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse);
    }

    /**
     * Retrieve when the contained <code>IdentityToken</code> was created.
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              ...
     *              &lt;wst:Lifetime&gt;
     *                  &lt;wsu:Created&gt;2011-07-23T15:32:12Z&lt;/wsu:Created&gt;
     *                  ...
     *              &lt;/wst:Lifetime&gt;
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;soap:Body&gt;
     * </pre>
     *
     * @return When the token was created.
     */
    public Date getCreated() {
        if(isFault()) {
            return null;
        }

        Element ac = getTag(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse, WSTTags.lifetime, WSUTags.created);
        return convertToDate(ac, null);
    }

    /**
     * Retrieve the AppliesTo element.
     *
     * @deprecated Use {@link #getAppliesTo()} instead
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              ...
     *              &lt;wsp:AppliesTo&gt;
     *                  &lt;wsa:EndpointReference&gt;
     *                      &lt;wsa:Address&gt;http://fmk-online.dk&lt;/wsa:Address&gt;
     *                  &lt;/wsa:EndpointReference&gt;
     *              &lt;/wsp:AppliesTo&gt;
     *              ...
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;soap:Body&gt;
     * </pre>
     *
     * @return The AppliesTo element value.
     */
    @Deprecated
    public String getEndPointAddress() {
        return getAppliesTo();
    }

    /**
     * Retrieve the AppliesTo element.
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              ...
     *              &lt;wsp:AppliesTo&gt;
     *                  &lt;wsa:EndpointReference&gt;
     *                      &lt;wsa:Address&gt;http://fmk-online.dk&lt;/wsa:Address&gt;
     *                  &lt;/wsa:EndpointReference&gt;
     *              &lt;/wsp:AppliesTo&gt;
     *              ...
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;soap:Body&gt;
     * </pre>
     *
     * @return The AppliesTo element value.
     */
    public String getAppliesTo() {
        if(isFault()) {
            return null;
        }

        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse, WSPTags.appliesTo, WSATags.endpointReference, WSATags.address);
    }

    /**
     * Retrieve when the contained <code>IdentityToken</code> expires.
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              ...
     *              &lt;wst:Lifetime&gt;
     *                  ...
     *                  &lt;wsu:Expires&gt;2011-07-23T15:37:12Z&lt;/wsu:Expires&gt;
     *              &lt;/wst:Lifetime&gt;
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;soap:Body&gt;
     * </pre>
     *
     * @return When the token expires.
     */
    public Date getExpires() {
        if(isFault()) {
            return null;
        }

        Element ac = getTag(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse, WSTTags.lifetime, WSUTags.expires);
        return convertToDate(ac, null);
    }

    /**
     * Retrieve the code uniquely identifying the fault type.<br />
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
     * @return The fault code - or <code>null</code> if the message is not fault message.
     */
    public String getFaultCode() {
        if(!isFault()) {
            return null;
        }

        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.body, SOAPTags.fault, CommonTags.faultcode);
    }

    /**
     * Retrieve the fault string - the detailed error message for the fault.<br />
     *
     * <pre>
     *   &lt;soap:Body&gt;
     *     &lt;soap:Fault&gt;
     *       &lt;faultstring&gt;Authentication failed: Token in request signed by untrusted party&lt;/faultstring&gt;
     *       ...
     *     &lt;/soap:Fault&gt;
     *   &lt;/soap:Body&gt;
     * </pre>
     *
     * @return The fault string - or <code>null</code> if the message is not fault message.
     */
    public String getFaultString() {
        if(!isFault()) {
            return null;
        }

        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.body, SOAPTags.fault, CommonTags.faultstring);
    }

    /**
     * Get the identity of the system reporting the fault.<br />
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
     * @return The fault factor - or <code>null</code> if the message is not fault message.
     */
    public String getFaultActor() {
        if(!isFault()) {
            return null;
        }

        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.body, SOAPTags.fault, CommonTags.faultactor);
    }

    /**
     * Retrieve the &quot;Relates to&quot; part of the SOAP header.
     *
     * <pre>
     *   &lt;soap:Header&gt;
     *     ...
     *     &lt;wsa:RelatesTo&gt;urn:uuid:99999999-0000-0000&lt;/wsa:RelatesTo&gt;
     *   &lt;/soap:Header&gt;
     * </pre>
     *
     * @return The <code>RelatesTo</code> value.
     */
    public String getRelatesTo() {
        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.header, WSATags.relatesTo);
    }

    /**
     * Retrieve the type of token retrieved.
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              &lt;wst:TokenType&gt;http://docs.oasis-open.org/wss/oasis-wss-saml-token- profile-1.1#SAMLV2.0&lt;/wst:TokenType&gt;
     *              ...
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;soap:Body&gt;
     * </pre>
     *
     * @return The token type.
     */
    public String getTokenType() {
        if(isFault()) {
            return null;
        }

        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse, WSTTags.tokenType);
    }

    /**
     * Retrieve whether the response from the server is a fault message.
     *
     * @return <code>true</code> if the message is an error message - otherwise <code>false</code>.
     */
    public boolean isFault() {
        if(fault == null) {
            fault = (getTag(SOAPTags.envelope, SOAPTags.body, SOAPTags.fault) != null);
        }
        return fault;
    }

    /**
     * Checks the signature on the <code>OIOWSTrustResponse</code> and whether the signing certificate is trusted.
     *
     * @param federation
     *            The Federation used to check trust for the <code>OIOWSTrustResponse</code>.
     *
     * @throws ModelException
     *             Thrown if the response is not signed or the signature on the <code>OIOWSTrustResponse</code> is invalid or the signing certificate is not trusted.
     */
    public void validateSignatureAndTrust(Federation federation) {
        LibertySignatureValidator validator = new LibertySignatureValidator(federation, dom);
        configureSignatureValidator(validator);
        validator.validateSignatureAndTrust();
    }

    @Override
    protected void configureSignatureValidator(LibertySignatureValidator validator) {
        validator.requireWSAddressingRelatesTo();
    }
}
