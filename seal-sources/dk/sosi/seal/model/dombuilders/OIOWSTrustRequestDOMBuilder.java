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

import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class OIOWSTrustRequestDOMBuilder<T extends OIOWSTrustRequestDOMBuilder> extends OIOWSTrustDOMBuilder{

    protected String audience;

    private String wsAddressingTo;

    /**
     * <b>Mandatory</b>: Set the <code>Audience</code> for the requested token.<br />
     * Example:
     *
     * <pre>
     *       &lt;soap:Body&gt;
     *          &lt;wst:RequestSecurityToken Context="urn:uuid:00000…"&gt;
     *              ...
     *              &lt;wsp:AppliesTo&gt;
     *                  &lt;wsa:EndpointReference&gt;
     *                      &lt;wsa:Address&gt;http://fmk-online.dk&lt;/wsa:Address&gt;
     *                  &lt;/wsa:EndpointReference&gt;
     *              &lt;/wsp:AppliesTo&gt;
     *          &lt;/wst:RequestSecurityToken&gt;
     *      &lt;/soap:Body&gt;
     * </pre&gt;
     *
     * @param audience
     *            The requested audience.
     * @return The <code>IdentityTokenRequestDOMBuilder</code> instance.
     */
    public T setAudience(String audience) {
        this.audience = audience;
        return (T) this;
    }

    /**
     * <b>Optional</b>: Set the WS-Addressing TO element denoting the STS endpoint.
     *
     * @param wsAddressingTo
     *            The WS-Addressing TO element denoting the STS endpoint.
     * @return The <code>IdentityTokenRequestDOMBuilder</code> instance.
     */
    public T setWSAddressingTo(String wsAddressingTo) {
        this.wsAddressingTo = wsAddressingTo;
        return (T) this;
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        validate("audience", audience);
        validateValue("wsAddressingTo", wsAddressingTo);
    }

    @Override
    protected void addExtraNamespaceDeclarations(Element envelope) {
        envelope.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_WST14, NameSpaces.WST_1_4_SCHEMA);
    }

    @Override
    protected void addExtraHeaders(Document doc, Element header) {
        if(wsAddressingTo != null) {
            final Element to = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.TO_PREFIXED);
            header.appendChild(to);
            to.setTextContent(wsAddressingTo);
        }
    }

    @Override
    protected void addBodyContent(Document doc, Element body) {
        final Element requestSecurityToken = addTokenRequest(doc, body);
        addActAs(doc, requestSecurityToken);
        addAudience(doc, requestSecurityToken);
        addClaims(doc, requestSecurityToken);
    }

    private Element addTokenRequest(Document doc, Element body) {
        final Element requestSecurityToken = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTrustTags.REQUEST_SECURITY_TOKEN_PREFIXED);
        requestSecurityToken.setAttributeNS(null, WSTrustAttributes.CONTEXT, XmlUtil.generateUUID());
        body.appendChild(requestSecurityToken);

        final Element tokenType = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTrustTags.TOKEN_TYPE_PREFIXED);
        requestSecurityToken.appendChild(tokenType);
        tokenType.setTextContent(WSSEValues.SAML_TOKEN_TYPE);

        final Element requestType = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTrustTags.REQUEST_TYPE_PREFIXED);
        requestSecurityToken.appendChild(requestType);
        requestType.setTextContent(WSTrustConstants.WST_1_3_ISSUE_REQUEST_TYPE);
        return requestSecurityToken;
    }

    private void addActAs(Document doc, Element requestSecurityToken) {
        final Element actAs = doc.createElementNS(NameSpaces.WST_1_4_SCHEMA, WSTrustTags.WST_1_4_ACT_AS_PREFIXED);
        requestSecurityToken.appendChild(actAs);
        addActAsTokens(doc, actAs);
    }

    protected abstract void addActAsTokens(Document doc, Element actAs);

    private void addAudience(Document doc, Element parent) {
        final Element appliesTo = doc.createElementNS(NameSpaces.WSP_SCHEMA, WSPTags.APPLIES_TO_PREFIXED);
        parent.appendChild(appliesTo);

        final Element endpointReference = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ENDPOINT_REFERENCE_PREFIXED);
        appliesTo.appendChild(endpointReference);

        final Element address = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ADDRESS_PREFIXED);
        endpointReference.appendChild(address);
        address.setTextContent(audience);
    }

    protected void addClaims(Document doc, Element requestSecurityToken) {};

}
