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

import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.model.constants.WSTTags;
import dk.sosi.seal.modelbuilders.IDCardModelBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLAssertionToIDCardResponse extends OIOWSTrustResponse {

    /**
     * Constructor for the <code>OIOSAMLAssertionToIDCardResponse</code> object.
     *
     * @param doc
     *            The DOM representation of the <code>OIOSAMLAssertionToIDCardResponse</code>.
     */
    public OIOSAMLAssertionToIDCardResponse(Document doc) {
        super(doc);
    }

    /**
     * Retrieve the contained <code>IDCard</code>.
     *
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              ...
     *              &lt;wst:RequestedSecurityToken&gt;
     *                  &lt;saml:Assertion IssueInstant=&quot;2012-10-23T15:32:12Z&quot; ...&gt;
     *                      ...
     *                  &lt;/saml:Assertion&gt;
     *              &lt;/wst:RequestedSecurityToken&gt;
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;/wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;/soap:Body&gt;
     * </pre>
     *
     * Note: No signature validation is performed on the <code>IDCard</code>
     *
     * @return The contained <code>IDCard</code> instance.
     */
    public IDCard getIDCard() {
        if (isFault()) {
            return null;
        }
        Element assertion = getTag(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse, WSTTags.requestedSecurityToken, SAMLTags.assertion);
        return assertion != null ? new IDCardModelBuilder().buildModel(assertion) : null;
    }

}
