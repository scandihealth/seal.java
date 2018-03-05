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

import dk.sosi.seal.model.IdentityTokenResponse;
import dk.sosi.seal.model.SchemaUtil;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.IOException;

/**
 * Builder class used for deconstructing an Identity token response <code>Document</code>.<br />
 * <br />
 * All operations related to constructing, wrapping, etc. of the <code>IdentityToken</code> should be done through the <code>IDWSHFactory</code>.
 * 
 * @author ads
 * @since 2.1
 */
public class IdentityTokenResponseModelBuilder {

    private static Schema schema;

    /**
     * Construct an <code>IdentityTokenResponse</code> from the supplied <code>Document</code>.
     * 
     * @param doc
     *            The <code>Document</code> to de-serialize into a <code>IdentityTokenResponse</code>.
     * @return The constructed <code>IdentityTokenResponse</code> instance.
     * @throws ModelBuildException
     *             Thrown if the <code>Document</code> is invalid.
     */
    public IdentityTokenResponse build(Document doc) throws ModelBuildException {
        validateSchema(doc);
        return new IdentityTokenResponse(doc);
    }

    private static synchronized Schema getSchema() throws SAXException {
        if (schema == null) {
            schema = SchemaUtil.loadSchema("/idwsh/idtresp/soap.xsd");
        }
        return schema;
    }

    private void validateSchema(Document doc) {
        try {
            final Validator validator = getSchema().newValidator();
            validator.validate(new DOMSource(doc));
        } catch (SAXException e) {
            throw new ModelBuildException("Error validating IdentityTokenResponse", e);
        } catch (IOException e) {
            throw new ModelBuildException("Error validating IdentityTokenResponse", e);
        }
    }
}