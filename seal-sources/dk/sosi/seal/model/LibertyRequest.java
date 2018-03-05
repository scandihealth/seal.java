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
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.text.ParseException;
import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LibertyRequest extends AbstractDOMInfoExtractor {

    public LibertyRequest(Federation federation, Document doc) {
        super(doc);
        final IdentityToken identityToken = getIdentityToken();
        identityToken.validateSignature(federation);

        //TODO always validate signature? Or only when the token is expired? Make this a parameter?
        LibertySignatureValidator validator = new LibertySignatureValidator(federation, doc.getDocumentElement());
        validator.requireFrameworkHeader();
        validator.requireReferenceToIdentityToken();
        validator.validateSignatureAndTrust();

        final Date now = new Date();
        if (now.before(identityToken.getNotBefore()) || ! now.before(identityToken.getNotOnOrAfter())) {
            validateLibertyTimestamp(identityToken);
        }
    }

    public IdentityToken getIdentityToken() {
        final Element assertion = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, SAMLTags.assertion);
        if (assertion == null) {
            throw new ModelBuildException("Could not find SAML assertion element");
        }
        return new IdentityToken(assertion);
    }

    public Date getCreatedTimestamp() {
        final Element createdTimestamp = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, WSUTags.timestamp, WSUTags.created);
        if (createdTimestamp == null) {
            throw new ModelBuildException("Could not find wsu:Created element");
        }
        try {
            return XmlUtil.fromXMLTimeStamp(createdTimestamp.getTextContent());
        } catch (ParseException e) {
            throw new ModelBuildException("Could not parse wsu:Created element", e);
        }
    }

    public String getMessageID() {
        final Element messageID = getTag(SOAPTags.envelope, SOAPTags.header, WSATags.messageID);
        if (messageID == null) {
            throw new ModelBuildException("Could not find " + NameSpaces.WSA_1_0_SCHEMA + "#MessageID element");
        }
        return messageID.getTextContent();
    }

    private void validateLibertyTimestamp(IdentityToken identityToken) {
        if (getCreatedTimestamp().before(identityToken.getNotBefore()) || getCreatedTimestamp().after(identityToken.getNotOnOrAfter())) {
            throw new ModelBuildException("Liberty timestamp (wsu:Created) is not within the Identity Tokens validity period");
        }
    }
}
