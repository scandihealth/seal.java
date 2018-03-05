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
import dk.sosi.seal.modelbuilders.IDCardModelBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class IDCardToOIOSAMLAssertionRequest extends OIOWSTrustRequest {

    public IDCardToOIOSAMLAssertionRequest(Document doc) {
        super(doc);
    }

    public UserIDCard getUserIDCard() {
        Element assertion = getTag(SOAPTags.envelope, SOAPTags.body, WSTTags.requestSecurityToken, WST14Tags.actAs, SAMLTags.assertion);
        // Check for IDCard in header
        if (assertion == null) {
            assertion = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, SAMLTags.assertion);
        }
        if (assertion == null) {
            throw new ModelException("Malformed request: IDCard could not be found!");
        }
        IDCard idCard = new IDCardModelBuilder().buildModel(assertion);
        if (!(idCard instanceof UserIDCard)) {
            throw new ModelException("IDCard in request is not a UserIDCard!");
        } else {
            return (UserIDCard) idCard;
        }
    }

}
