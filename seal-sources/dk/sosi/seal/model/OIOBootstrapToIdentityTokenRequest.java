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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.List;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOBootstrapToIdentityTokenRequest extends OIOWSTrustRequest {

    public OIOBootstrapToIdentityTokenRequest(Document doc) {
        super(doc);
    }

    public OIOBootstrapToken getOIOBootstrapToken() {
        Element assertionElm = getTag(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityToken, WST14Tags.actAs, SAMLTags.assertion);
        return new OIOBootstrapToken(assertionElm);
    }

    public String getCPRNumberClaim() {
        List<Element> claims = getTags(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityToken, WSTTags.claims, WSFAuthTags.claimType);
        for (Element claim: claims) {
            if (OIOSAMLAttributes.CPR_NUMBER.equals(claim.getAttribute(WSFAuthAttributes.URI))) {
                return claim.getTextContent();
            }
        }
        return null;
    }
}
