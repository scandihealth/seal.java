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
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.IdentityTokenRequest;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.SchemaUtil;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.IOException;

/**
 * Builder class used for building an Identity Token Request from a <code>Document</code>.<br />
 *
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class IdentityTokenRequestModelBuilder {

    private final Federation federation;

    /**
     * Sole constructor
     *
     * @param federation
     *          The federation to check 'trust' against for the idcard in the request
     */
    public IdentityTokenRequestModelBuilder(Federation federation) {
        this.federation = federation;
    }

    private static Schema schema;

    /**
     *  Builds an <code>IdentityTokenRequest</code> from the supplied <code>Document</code>, checks the signature of
     *  the <code>IDCard</code> in the request and verifies that the certificate used to sign the <code>IDCard</code>
     *  is trusted.
     *  </br>
     *  Validity in time is not checked, as there may be different lifetime requirements depending on the requested
     *  audience.
     *
     * @param document
     * @return
     *          The constructed <code>IdentityTokenRequest</code>
     */
    public IdentityTokenRequest buildModel(Document document) {

        schemaValidate(document);

        final Element header = XmlUtil.getFirstChildElementNS(document.getDocumentElement(), NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED);
        final Element messageID = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID);

        final Element body = XmlUtil.getFirstChildElementNS(document.getDocumentElement(), NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_UNPREFIXED);
        final Element requestSecurityToken = XmlUtil.getFirstChildElementNS(body, NameSpaces.WST_1_3_SCHEMA, WSTrustTags.REQUEST_SECURITY_TOKEN);
        final String context = requestSecurityToken.getAttribute(WSTrustAttributes.CONTEXT);
        final Element appliesTo = XmlUtil.getFirstChildElementNS(requestSecurityToken, NameSpaces.WSP_SCHEMA, WSPTags.APPLIES_TO);
        final Element address = (Element) appliesTo.getFirstChild().getFirstChild();

        Element assertion;
        final Element security = XmlUtil.getFirstChildElementNS(header, NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY);
        if (security != null) {
            // idcard in header
            assertion = (Element) security.getFirstChild();
        } else {
            // idcard in body
            final Element actAs = XmlUtil.getFirstChildElementNS(requestSecurityToken, NameSpaces.WST_1_4_SCHEMA, WSTrustTags.WST_1_4_ACT_AS);
            assertion = XmlUtil.getFirstChildElementNS(actAs, NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION);
            if (assertion == null) {
                throw  new ModelBuildException("Expected idCard under wst14:ActAs");
            }
        }
        final IDCard idCard = new IDCardModelBuilder().buildModel(assertion);
        try {
            idCard.validateSignatureAndTrust(federation);
        } catch (ModelException e) {
            throw new ModelBuildException(e.getMessage());
        }

        return new IdentityTokenRequest(idCard, messageID != null ? messageID.getTextContent() : null, address.getTextContent(), context);
    }

    private void schemaValidate(Document envelope) {
        try {
            final Validator validator = getSchema().newValidator();
            validator.validate(new DOMSource(envelope));
        } catch (SAXException e) {
            throw new ModelBuildException("Error validating IdentityTokenRequest", e);
        } catch (IOException e) {
            throw new ModelBuildException("Error validating IdentityTokenRequest", e);
        }

    }

    private static synchronized Schema getSchema() throws SAXException {
        if (schema == null) {
            schema = SchemaUtil.loadSchema("/idwsh/idtreq/soap.xsd");
        }
        return schema;
    }

}