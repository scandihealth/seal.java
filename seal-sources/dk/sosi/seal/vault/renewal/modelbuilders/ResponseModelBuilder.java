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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/modelbuilders/ResponseModelBuilder.java $
 * $Id: ResponseModelBuilder.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.modelbuilders;

import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.renewal.model.Response;
import dk.sosi.seal.vault.renewal.model.dombuilders.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;


/**
 * Class to build renewal response model objects from DOM representations.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class ResponseModelBuilder extends MessageModelBuilder { //NOPMD
	
	/**
	 * Build a message model object
	 * @param doc
	 * 		DOM representation of the renewal response message object
	 * @return The constructed <code>Response</code> object.
	 * @throws ModelBuildException
	 */
	public Response buildModel(Document doc) throws ModelBuildException {

		NodeList results = doc.getElementsByTagName("result");
		if(results.getLength() != 1) {
			throw new ModelBuildException("Wrong number of result elements in response.");
		}
			
		Node result = results.item(0);
		String rType = getResponseType(result);
		
		try {
			
			Class<?> responseType =  Class.forName(rType);
			Constructor<?> constructor =  responseType.getConstructor(new Class[]{});
			Response response = (Response) constructor.newInstance(new Object[]{});
			
			NodeList fields = result.getChildNodes();
			for(int i = 0; i < fields.getLength(); i++) {
				if(fields.item(i).getAttributes() != null) {
					setField(response, fields.item(i));
				}
			}

			
			return response;
			
		} catch (ClassNotFoundException e) {
			throw new ModelBuildException("Failed to construct response", e);
		} catch (SecurityException e) {
			throw new ModelBuildException("Failed to construct response", e);
		} catch (NoSuchMethodException e) {
			throw new ModelBuildException("Failed to construct response", e);		
		} catch (IllegalArgumentException e) {
			throw new ModelBuildException("Failed to construct response", e);
		} catch (InstantiationException e) {
			throw new ModelBuildException("Failed to construct response", e);
		} catch (IllegalAccessException e) {
			throw new ModelBuildException("Failed to construct response", e);
		} catch (InvocationTargetException e) {
			throw new ModelBuildException("Failed to construct response", e);
		}

		
		
	}
	
	

	/**
	 * Compute the name of the response model class to instantiate
	 * @param result
	 * 		The result DOM element 
	 * @return
	 * 		Name of response class
	 */
	private String getResponseType(Node result) {
		String usedPackage = Response.class.getPackage().getName();
		String responseType = result.getAttributes().getNamedItem(Constants.XSI_TYPE).getNodeValue();
		
		responseType = responseType.split(":")[1];
		return usedPackage + "." + responseType;
	}

	
}
