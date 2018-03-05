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
import org.w3c.dom.Document;

/**
 * Model object representing a response on an <code>IdentityToken</code> request.<br />
 * The <code>IdentityTokenResponse</code> read values directly from the underlying DOM.<br />
 * <br />
 * All operations related to constructing, wrappring, etc. of the <code>IdentityToken</code> should be done through the <code>IDWSHFactory</code>.
 * 
 * @author ads
 * @version $Revision:$
 * @since 2.1
 */
public class IdentityTokenResponse extends OIOWSTrustResponse {

    /**
     * Constructor for the <code>IdentityTokenResponse</code> object.
     * 
     * @param doc
     *            The DOM representation of the <code>IdentityTokenResponse</code>.
     */
    public IdentityTokenResponse(Document doc) {
        super(doc);
    }

    /**
     * Retrieve the contained <code>IdentityToken</code>.
     * 
     * <pre>
     *  &lt;soap:Body&gt;
     *      &lt;wst:RequestSecurityTokenResponseCollection&gt;
     *          &lt;wst:RequestSecurityTokenResponse ...&gt;
     *              ...
     *              &lt;wst:RequestedSecurityToken&gt;
     *                  &lt;saml:Assertion IssueInstant=&quot;2011-07-23T15:32:12Z&quot; ...&gt;
     *                      ...
     *                  &lt;/saml:Assertion&gt;
     *              &lt;/wst:RequestedSecurityToken&gt;
     *          &lt;/wst:RequestSecurityTokenResponse ...&gt;
     *      &lt;/wst:RequestSecurityTokenResponseCollection&gt;
     *  &lt;/soap:Body&gt;
     * </pre>
     * 
     * @return The contained <code>IdentityToken</code> instance.
     */
    public IdentityToken getIdentityToken() {
        if(isFault()) {
            return null;
        }

        return new IdentityToken(getTag(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityTokenResponseCollection, WSTTags.requestSecurityTokenResponse, WSTTags.requestedSecurityToken, SAMLTags.assertion));
    }

}