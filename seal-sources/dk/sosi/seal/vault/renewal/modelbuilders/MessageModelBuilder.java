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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/modelbuilders/MessageModelBuilder.java $
 * $Id: MessageModelBuilder.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.vault.renewal.modelbuilders;

import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.renewal.model.Message;
import dk.sosi.seal.vault.renewal.model.dombuilders.Constants;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Node;

import java.lang.reflect.InvocationTargetException;

/**
 * Class to build renewal model objects from DOM representations.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class MessageModelBuilder { //NOPMD

	/**
	 * Generic setter method, which will invoke an appropriate setter on the passed
	 * target, based on name and type of the passed node.
	 * 
	 * @param target <code>Message</code> target.
	 * @param field <code>Node</code> field.
	 * @throws ModelBuildException
	 */
	protected void setField(Message target, Node field) throws ModelBuildException {

		try {
			Class<?> type = getFieldType(field);
			//If type is undeterminable, the field should not be set.
			if(type != null) {
				Object value = getFieldValue(field);
				if(value instanceof Integer) {
					target.setField(field.getNodeName(), ((Integer) value).intValue());
				} else {
					target.setField(field.getNodeName(), type, value);
				}
			}
		} catch (SecurityException e) {
			throw new ModelBuildException("Failed to set field", e);
		} catch (IllegalArgumentException e) {
			throw new ModelBuildException("Failed to set field", e);
		} catch (NoSuchMethodException e) {
			throw new ModelBuildException("Failed to set field", e);
		} catch (IllegalAccessException e) {
			throw new ModelBuildException("Failed to set field", e);
		} catch (InvocationTargetException e) {
			throw new ModelBuildException("Failed to set field", e);
		}
	}
	
	/**
	 * Returns the field value of the passed node
	 * @param field The <code>Node</code>
	 * @return <code>Object</code> containing the field value.
	 * @throws ModelBuildException
	 */
	protected Object getFieldValue(Node field) throws ModelBuildException {
		String type = field.getAttributes().getNamedItem(Constants.XSI_TYPE).getNodeValue();
		if(field.getChildNodes().item(0) == null) return null; //NOPMD
		String value = field.getChildNodes().item(0).getNodeValue();
		Object fieldValue;
		if(type.equals(Constants.XSD_STRING)) {
			fieldValue = value;
		} else if(type.equals(Constants.XSD_INT)) {
			fieldValue = new Integer(value);
		} else if(type.equals(Constants.XSD_BASE64BINARY)) {
			fieldValue = XmlUtil.fromBase64(value);
		} else {
			throw new ModelBuildException("Unsupported xsi_type: " + type);
		}
		return fieldValue;
	}

	/**
	 * Returns the field type of the passed node
	 * @param field The <code>Node</code>.
	 * @return <code>Class</code> object representing the field type. 
	 * @throws ModelBuildException
	 */
	protected Class<?> getFieldType(Node field) throws ModelBuildException {
		Node fieldTypeAttribute = field.getAttributes().getNamedItem(Constants.XSI_TYPE);
		if(fieldTypeAttribute == null) {
			return null;  //NOPMD
		}
		String type = fieldTypeAttribute.getNodeValue();
		Class<?> fieldType;
		if(type.equals(Constants.XSD_STRING)) {
			fieldType = String.class;
		} else if(type.equals(Constants.XSD_INT)) {
			fieldType = Integer.TYPE;
		} else if(type.equals(Constants.XSD_BASE64BINARY)) {
			fieldType = byte[].class;
		} else {
			throw new ModelBuildException("Unsupported xsi_type: " + type);
		}
		return fieldType;
	}


}
