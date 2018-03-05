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
import dk.sosi.seal.model.OIOBootstrapToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOBootstrapToIdentityTokenRequestDOMBuilder extends AbstractOIOToIdentityTokenRequestDOMBuilder<OIOBootstrapToIdentityTokenRequestDOMBuilder>{

    private OIOBootstrapToken bootstrapToken;

    public OIOBootstrapToIdentityTokenRequestDOMBuilder setOIOBootstrapToken(OIOBootstrapToken bootstrapToken) {
        this.bootstrapToken = bootstrapToken;
        return this;
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        super.validateBeforeBuild();
        validate("OIOBootstrapToken", bootstrapToken);
    }

    @Override
    protected void addActAsTokens(Document doc, Element actAs) {
        addOIOBootstrapToken(doc, actAs);
    }

    private void addOIOBootstrapToken(Document doc, Element actAs) {
        actAs.appendChild(doc.importNode(bootstrapToken.getDOM().getDocumentElement(), true));
    }

}
