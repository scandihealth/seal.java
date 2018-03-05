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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/RenewalFactory.java $
 * $Id: RenewalFactory.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.renewal.model.IssueResult;
import dk.sosi.seal.vault.renewal.model.RenewalAuthorization;
import dk.sosi.seal.vault.renewal.model.Request;
import dk.sosi.seal.vault.renewal.model.Response;
import dk.sosi.seal.vault.renewal.model.dombuilders.RequestDOMBuilder;
import dk.sosi.seal.vault.renewal.modelbuilders.ResponseModelBuilder;
import dk.sosi.seal.xml.XmlUtil;
import dk.sosi.seal.xml.XmlUtilException;

import java.util.Properties;

/**
 * Factory used to serialize and deserialize renewal SOAP messages. 
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class RenewalFactory {
	
	/**
	 * Serialize a request to a SOAP string.
	 * @param request model object to be converted to SOAP message
	 * @return SOAP string
	 */
	public static String serializeRequest(Request request) {
		RequestDOMBuilder builder = new RequestDOMBuilder(XmlUtil.createEmptyDocument(), request);
		return XmlUtil.node2String(builder.buildDocument(),false, true);
	}

	/**
	 * Deserialize a renew certificate response.
	 * @param xml
	 * 		SOAP message to be converted into model object
	 * @param properties 
	 * @return The deserialized <code>IssueResult</code> object.
	 * @throws XmlUtilException Thrown if a problem arises
	 * @throws ModelBuildException Thrown if a problem arises
	 */
	public static IssueResult deserializeRenewCertificateResponse(Properties properties, String xml) throws XmlUtilException, ModelBuildException {
		ResponseModelBuilder builder = new ResponseModelBuilder();
		Response resp = builder.buildModel(XmlUtil.readXml(properties, xml, false));
		return (IssueResult) resp;
		
	}

	/**
	 * Deserialize a request renewal response.
	 * @param xml
	 * 		SOAP message to be converted into model object
	 * @return The deserialized <code>RenewalAuthorization</code> object.
	 * @throws XmlUtilException Thrown if a problem arises
	 * @throws ModelBuildException Thrown if a problem arises
	 */
	public static RenewalAuthorization deserializeRequestRenewalResponse(Properties properties, String xml) throws XmlUtilException, ModelBuildException {
		ResponseModelBuilder builder = new ResponseModelBuilder();
		Response resp = builder.buildModel(XmlUtil.readXml(properties, xml, false));
		return (RenewalAuthorization) resp;
	}

}
