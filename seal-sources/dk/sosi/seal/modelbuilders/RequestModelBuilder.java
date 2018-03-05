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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/RequestModelBuilder.java $
 * $Id: RequestModelBuilder.java 20605 2014-10-24 12:30:53Z ChristianGasser $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.MedComTags;
import dk.sosi.seal.model.constants.NameSpaces;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Builds <code>Request</code> model objects from a DOM document.
 *
 * @author Jan
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */

public class RequestModelBuilder extends MessageModelBuilder {

	public RequestModelBuilder(SOSIFactory fac) {

		super(fac);
	}

	/**
	 * Builds a Request objects from a DOM document.
	 *
	 * @param doc
	 *            The DOM document used for the Request.
	 */
	public Request buildModel(Document doc) throws ModelBuildException {

		// Extract parameters

		boolean noRep = false;
        Node node = doc.getElementsByTagNameNS(NameSpaces.MEDCOM_SCHEMA, MedComTags.REQUIRE_NON_REPUDIATION_RECEIPT).item(0);
        if (node != null) {
        	String noRepString = node.getChildNodes().item(0).getNodeValue();
        	noRep = !"no".equals(noRepString);
        }

		Request request = factory.createNewRequest(noRep, null);

		// Message parameters
		super.buildModel(request, doc);

		if (AuthenticationLevel.MOCES_TRUSTED_USER.equals(request.getIDCard().getAuthenticationLevel()) ||
				AuthenticationLevel.VOCES_TRUSTED_SYSTEM.equals(request.getIDCard().getAuthenticationLevel())) {
			// Validate Signatures
			NodeList signatures = doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);
			if (signatures.getLength() == 0)
				// In SOSI authlvl 3-4, signatures are mandatory on requests
				throw new SignatureInvalidModelBuildException("ID Card has no signature", request.getMessageID(), request.getFlowID(), request.getDGWSVersion());
			SignatureUtil.validateAllSignatures(request, signatures, factory.getFederation(), factory.getCredentialVault(),true);
		}
		return request;
	}
}
