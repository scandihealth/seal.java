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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/modelbuilders/RequestModelBuilder.java $
 * $Id: RequestModelBuilder.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.modelbuilders;

import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.renewal.model.Request;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * Class to build renewal request model objects from DOM representations.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class RequestModelBuilder extends MessageModelBuilder { //NOPMD

	/**
	 * Build a message model object
	 * @param doc
	 * 		DOM representation of the renewal message object
	 * @return The constructed <code>Request</code> object.
	 * @throws ModelBuildException
	 */
	public Request buildModel(Document doc) throws ModelBuildException {

		NodeList methods = doc.getElementsByTagNameNS(NameSpaces.SOAP_SCHEMA, "Body").item(0).getChildNodes();
		if(methods.getLength() != 1) {
			throw new ModelBuildException("Wrong number of result elements in request.");
		}
			
		Node result = methods.item(0);
		String rType = getRequestType(result);
		
		try {
			
			Class<?> requestType =  Class.forName(rType);
			
			NodeList fields = result.getChildNodes();
			Object[] constructorArgs = new Object[fields.getLength()];
			Class<?>[] constructorArgTypes = new Class[fields.getLength()];
			for(int i = 0; i < fields.getLength(); i++) {
				constructorArgs[i] = getFieldValue(fields.item(i));
				constructorArgTypes[i] = constructorArgs[i].getClass();
			}
			
			Constructor<?> constructor =  requestType.getConstructor(constructorArgTypes);
			return (Request) constructor.newInstance(constructorArgs);
		} catch (ClassNotFoundException e) {
			throw new ModelBuildException("Failed to construct request", e);
		} catch (SecurityException e) {
			throw new ModelBuildException("Failed to construct request", e);
		} catch (NoSuchMethodException e) {
			throw new ModelBuildException("Failed to construct request", e);		
		} catch (IllegalArgumentException e) {
			throw new ModelBuildException("Failed to construct request", e);
		} catch (InstantiationException e) {
			throw new ModelBuildException("Failed to construct request", e);
		} catch (IllegalAccessException e) {
			throw new ModelBuildException("Failed to construct request", e);
		} catch (InvocationTargetException e) {
			throw new ModelBuildException("Failed to construct request", e);
		}
		
	}

	/**
	 * Compute the name of the model class to build an instance of
	 * @param method 
	 * 		The method element from XML 
	 * @return
	 * 		Name of model class
	 */
	private String getRequestType(Node method) {
		String usedPackage = Request.class.getPackage().getName();
		String requestType = method.getNodeName().split(":")[1];
		requestType = requestType.substring(0, 1).toUpperCase() + requestType.substring(1) + "Request";
		return usedPackage + "." + requestType;
	}
}
