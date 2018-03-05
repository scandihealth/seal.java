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

import dk.sosi.seal.model.IDCardValidator;
import dk.sosi.seal.model.UserIDCard;

/**
 * Builder class used for creating an Identity token request.<br />
 * <br />
 * This class is not thread safe.<br />
 * An <code>IdentityTokenRequestDOMBuilder</code> should be created for each <code>IdentityTokenRequest</code> needed. <br />
 * All operations related to constructing, wrappring, etc. of the <code>IdentityToken</code> should be done through the <code>IDWSHFactory</code>.
 * 
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class IdentityTokenRequestDOMBuilder extends IDCardOIOWSTrustRequestDOMBuilder<IdentityTokenRequestDOMBuilder> {

    /**
     * <b>Mandatory</b>: Set the <code>UserIDCard</code> to be exchanged to an IdentityToken.
     *
     * @param idCard
     *            The STS-signed UserIDCard.
     * @return The <code>IdentityTokenRequestDOMBuilder</code> instance.
     * @deprecated use @link(#setUserIDCard) instead
     */
    @Deprecated
    public IdentityTokenRequestDOMBuilder setUserIdCard(UserIDCard idCard) {
        return setUserIDCard(idCard);
    }

    /**
     * <b>Optional</b>: Whether the <code>IdentityTokenRequest</code> should follow DenGodeWebservice and place the
     * <code>IdCard</code> in the SOAP header. Must be set to 'true' if the <code>IdentityTokenRequest</code> is sent
     * through SOSI-GW.
     *
     * @param dgwsStyle
     *            Whether to place the <code>IdCard</code> in the SOAP header.
     * @return The <code>IdentityTokenRequestDOMBuilder</code> instance.
     * @deprecated use @link(#requireIDCardInSOAPHeader) instead
     */
    @Deprecated
    public IdentityTokenRequestDOMBuilder setDgwsStyle(boolean dgwsStyle) {
        this.placeIDCardInSOAPHeader = dgwsStyle;
        return this;
    }

    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        new IDCardValidator().validateIDCard(idCard);
    }

}