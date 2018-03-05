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

package dk.sosi.seal;

import dk.sosi.seal.model.CitizenIdentityTokenBuilder;
import dk.sosi.seal.model.OIOSAMLAssertionBuilder;
import dk.sosi.seal.model.dombuilders.*;
import dk.sosi.seal.modelbuilders.*;

/**
 * The <code>OIOSAMLFactory</code> is the entry class for obtaining builders for creating or parsing OIOWSTrust requests
 * and responses used to exchange OIOSAML assertions to SOSI IDCards
 *
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLFactory {
	
	// OIO Bootstrap token to IDWS Identity Token
    public OIOBootstrapToIdentityTokenRequestDOMBuilder createOIOBootstrapToIdentityTokenRequestDOMBuilder() {
        return new OIOBootstrapToIdentityTokenRequestDOMBuilder();
    }

    public OIOBootstrapToIdentityTokenRequestModelBuilder createOIOBootstrapToIdentityTokenRequestModelBuilder() {
        return new OIOBootstrapToIdentityTokenRequestModelBuilder();
    }
    
    public OIOBootstrapToIdentityTokenResponseDOMBuilder createOIOBootstrapToIdentityTokenResponseDOMBuilder() {
        return new OIOBootstrapToIdentityTokenResponseDOMBuilder();
    }

    public OIOBootstrapToIdentityTokenResponseModelBuilder createOIOBootstrapToIdentityTokenResponseModelBuilder() {
        return new OIOBootstrapToIdentityTokenResponseModelBuilder();
    }
    // end


    // Encrypted OIOAssertion to IDWS Identity Token
    public EncryptedOIOSAMLAssertionToIdentityTokenRequestDOMBuilder createEncryptedOIOSAMLAssertionToIdentityTokenRequestDOMBuilder() {
        return new EncryptedOIOSAMLAssertionToIdentityTokenRequestDOMBuilder();
    }

    public EncryptedOIOSAMLAssertionToIdentityTokenRequestModelBuilder createEncryptedOIOSAMLAssertionToIdentityTokenRequestModelBuilder() {
        return new EncryptedOIOSAMLAssertionToIdentityTokenRequestModelBuilder();
    }

    public EncryptedOIOSAMLAssertionToIdentityTokenResponseDOMBuilder createEncryptedOIOSAMLAssertionToIdentityTokenResponseDOMBuilder() {
        return new EncryptedOIOSAMLAssertionToIdentityTokenResponseDOMBuilder();
    }

    public EncryptedOIOSAMLAssertionToIdentityTokenResponseModelBuilder createEncryptedOIOSAMLAssertionToIdentityTokenResponseModelBuilder() {
        return new EncryptedOIOSAMLAssertionToIdentityTokenResponseModelBuilder();
    }
    // end


    /**
     * Creates a new <code>OIOSAMLAssertionToIDCardRequestDOMBuilder</code>
     *
     * @return  The newly created <code>OIOSAMLAssertionToIDCardRequestDOMBuilder</code>
     */
    public OIOSAMLAssertionToIDCardRequestDOMBuilder createOIOSAMLAssertionToIDCardRequestDOMBuilder() {
        return new OIOSAMLAssertionToIDCardRequestDOMBuilder();
    }

    /**
     * Creates a new <code>OIOSAMLAssertionToIDCardRequestModelBuilder</code>
     *
     * @return  The newly created <code>OIOSAMLAssertionToIDCardRequestModelBuilder</code>
     */
    public OIOSAMLAssertionToIDCardRequestModelBuilder createOIOSAMLAssertionToIDCardRequestModelBuilder() {
        return new OIOSAMLAssertionToIDCardRequestModelBuilder();
    }

    /**
     * Creates a new <code>OIOSAMLAssertionToIDCardResponseDOMBuilder</code>
     *
     * @return  The newly created <code>OIOSAMLAssertionToIDCardResponseDOMBuilder</code>
     */
    public OIOSAMLAssertionToIDCardResponseDOMBuilder createOIOSAMLAssertionToIDCardResponseDOMBuilder() {
        return new OIOSAMLAssertionToIDCardResponseDOMBuilder();
    }

    /**
     * Creates a new <code>OIOSAMLAssertionToIDCardResponseModelBuilder</code>
     *
     * @return  The newly created <code>OIOSAMLAssertionToIDCardResponseModelBuilder</code>
     */
    public OIOSAMLAssertionToIDCardResponseModelBuilder createOIOSAMLAssertionToIDCardResponseModelBuilder() {
        return new OIOSAMLAssertionToIDCardResponseModelBuilder();
    }


    /**
     * Creates a new <code>IDCardToOIOSAMLAssertionRequestDOMBuilder</code>
     *
     * @return  The newly created <code>IDCardToOIOSAMLAssertionRequestDOMBuilder</code>
     */
    public IDCardToOIOSAMLAssertionRequestDOMBuilder createIDCardToOIOSAMLAssertionRequestDOMBuilder() {
        return new IDCardToOIOSAMLAssertionRequestDOMBuilder();
    }

    /**
     * Creates a new <code>IDCardToOIOSAMLAssertionRequestModelBuilder</code>
     *
     * @return  The newly created <code>IDCardToOIOSAMLAssertionRequestModelBuilder</code>
     */
    public IDCardToOIOSAMLAssertionRequestModelBuilder createIDCardToOIOSAMLAssertionRequestModelBuilder() {
        return new IDCardToOIOSAMLAssertionRequestModelBuilder();
    }

    /**
     * Creates a new <code>IDCardToOIOSAMLAssertionResponseDOMBuilder</code>
     *
     * @return  The newly created <code>IDCardToOIOSAMLAssertionResponseDOMBuilder</code>
     */
    public IDCardToOIOSAMLAssertionResponseDOMBuilder createIDCardToOIOSAMLAssertionResponseDOMBuilder() {
        return new IDCardToOIOSAMLAssertionResponseDOMBuilder();
    }

    /**
     * Creates a new <code>IDCardToOIOSAMLAssertionRequestModelBuilder</code>
     *
     * @return  The newly created <code>IDCardToOIOSAMLAssertionRequestModelBuilder</code>
     */
    public IDCardToOIOSAMLAssertionResponseModelBuilder createIDCardToOIOSAMLAssertionResponseModelBuilder() {
        return new IDCardToOIOSAMLAssertionResponseModelBuilder();
    }

    /**
     * Creates a new <code>OIOSAMLAssertionBuilder</code>
     *
     * @return  The newly created <code>OIOSAMLAssertionBuilder</code>
     */
    public OIOSAMLAssertionBuilder createOIOSAMLAssertionBuilder() {
        return new OIOSAMLAssertionBuilder();
    }

    public CitizenIdentityTokenBuilder createCitizenIdentityTokenBuilder() {
        return new CitizenIdentityTokenBuilder();
    }

    /**
     * Creates a new <code>UnsolicitedResponseDOMBuilder</code>
     *
     * @return  The newly created <code>UnsolicitedResponseDOMBuilder</code>
     */
    public UnsolicitedResponseDOMBuilder createUnsolicitedResponseDOMBuilder() {
        return new UnsolicitedResponseDOMBuilder();
    }
}
