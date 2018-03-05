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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/SecurityTokenResponseModelBuilder.java $
 * $Id: SecurityTokenResponseModelBuilder.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SecurityTokenResponse;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.text.ParseException;
import java.util.Date;

/**
 * Build the Model assuming compliance with SOSI SecurityTokenResponse format
 *
 * @author Peter Buus
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SecurityTokenResponseModelBuilder extends MessageModelBuilder {

    private final boolean validateTrust;

    @Deprecated
    public SecurityTokenResponseModelBuilder(SOSIFactory fac) {
        this(fac, true);
    }


    public SecurityTokenResponseModelBuilder(SOSIFactory fac, boolean validateTrust) {
        super(fac);
        this.validateTrust = validateTrust;
    }

    /**
	 * Builds a SecurityTokenResponse objects from a DOM document.
	 *
	 * @param doc
	 *            The DOM document used for the Reply.
	 */
	public SecurityTokenResponse buildModel(Document doc) throws ModelBuildException {

		ModelPrefixResolver modelPrefixResolver = new ModelPrefixResolver();

		// Get soap:Header

		Element elmSoapHeader = XmlUtil.selectSingleElement(doc, "//" + NameSpaces.NS_SOAP + ":Envelope/" + NameSpaces.NS_SOAP + ":Header", modelPrefixResolver, true);

		// Get creation date
		Element elmCreated = XmlUtil.selectSingleElement(elmSoapHeader, "wsse:Security/wsu:Timestamp/wsu:Created", modelPrefixResolver, true);

		String xmlTimestamp = XmlUtil.getTextNodeValue(elmCreated);
		Date created;
		try {
			created = XmlUtil.fromXMLTimeStamp(xmlTimestamp);
		} catch (ParseException e) {
			throw new ModelBuildException("Unable to parse timestamp from <wsu:Created>", e);
		}

		String dgwsVersion = XmlUtil.isZuluTimeFormat(xmlTimestamp) ? DGWSConstants.VERSION_1_0_1 : DGWSConstants.VERSION_1_0;

		String inResponseToMessageID = ((Element) doc.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, "Security").item(0)).getAttribute("id");

		Element elmFaultCode, elmFaultString, elmFaultActor;
		SecurityTokenResponse securityTokenResponse;

		// This could be a fault. Check for soap:Fault in the body.
		Element fault = XmlUtil.selectSingleElement(doc, "//" + SOAPTags.BODY_PREFIXED + '/' + SOAPTags.FAULT_PREFIXED, modelPrefixResolver, false);
		if (fault != null) {

			elmFaultCode = XmlUtil.selectSingleElement(fault, SOAPTags.FAULTCODE, modelPrefixResolver, false);
			elmFaultString = XmlUtil.selectSingleElement(fault, SOAPTags.FAULTSTRING, modelPrefixResolver, false);
			elmFaultActor = XmlUtil.selectSingleElement(fault, SOAPTags.FAULTACTOR, modelPrefixResolver, false);

			if (elmFaultCode == null)
				throw new ModelBuildException("No " + SOAPTags.FAULTCODE + " in " + SOAPTags.FAULT_PREFIXED);

			if (elmFaultString == null)
				throw new ModelBuildException("No " + SOAPTags.FAULTSTRING + " in " + SOAPTags.FAULT_PREFIXED);

			if (elmFaultActor == null)
				throw new ModelBuildException("No " + SOAPTags.FAULTACTOR + " in " + SOAPTags.FAULT_PREFIXED);

			securityTokenResponse = factory.createNewSecurityTokenErrorResponse(dgwsVersion, inResponseToMessageID, XmlUtil.getTextNodeValue(elmFaultCode),
					XmlUtil.getTextNodeValue(elmFaultString), XmlUtil.getTextNodeValue(elmFaultActor));
		} else {
			securityTokenResponse = factory.createNewSecurityTokenResponse(dgwsVersion, inResponseToMessageID);
		}

		securityTokenResponse.setCreationDate(created);

		// Message parameters
		super.buildModel(securityTokenResponse, doc);

		// Validate Signature
		SignatureUtil.validateAllSignatures(securityTokenResponse, doc.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE), factory
				.getFederation(), factory.getCredentialVault(), validateTrust);

		return securityTokenResponse;
	}
}
