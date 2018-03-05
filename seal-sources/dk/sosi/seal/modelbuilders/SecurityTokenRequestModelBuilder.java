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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/SecurityTokenRequestModelBuilder.java $
 * $Id: SecurityTokenRequestModelBuilder.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.SecurityTokenRequest;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.NameSpaces;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Builds <code>Request</code> model objects from a DOM document.
 *
 * @author Jan
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */

public class SecurityTokenRequestModelBuilder extends MessageModelBuilder {

	public SecurityTokenRequestModelBuilder(SOSIFactory fac) {

		super(fac);
	}

	/**
	 * Builds a Request objects from a DOM document.
	 *
	 * @param doc
	 *            The DOM document used for the Request.
	 */
	public SecurityTokenRequest buildModel(Document doc) throws ModelBuildException {

		SecurityTokenRequest securityTokenRequest = factory.createNewSecurityTokenRequest();

		// Message parameters
		super.buildModel(securityTokenRequest, doc);

		AuthenticationLevel authenticationLevel = securityTokenRequest.getIDCard().getAuthenticationLevel();
		if(AuthenticationLevel.MOCES_TRUSTED_USER.equals(authenticationLevel) ||
				AuthenticationLevel.VOCES_TRUSTED_SYSTEM.equals(authenticationLevel)) {

			// Validate Signatures
			NodeList signatures = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);
			if (signatures.getLength() == 0) {
				// In SOSI signatures are mandatory on requests
				throw new SignatureInvalidModelBuildException("SecurityTokenRequest has no signature", securityTokenRequest.getMessageID(),
						securityTokenRequest.getFlowID(), securityTokenRequest.getDGWSVersion());
			} else if (signatures.getLength() > 1) {
				// In SOSI signatures are mandatory on requests
				throw new SignatureInvalidModelBuildException("SecurityTokenRequest has multiple signatures", securityTokenRequest.getMessageID(),
						securityTokenRequest.getFlowID(), securityTokenRequest.getDGWSVersion());
			} else {
				SignatureUtil.validateAllSignatures(securityTokenRequest, signatures, factory.getFederation(), factory.getCredentialVault(),false);
			}
		}

		return securityTokenRequest;
	}
}
