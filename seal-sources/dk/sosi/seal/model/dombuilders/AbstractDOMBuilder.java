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

import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.Tag;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Abstract base class for builder classes.
 * 
 * @author ads
 * 
 * @param <T>
 *            The type of object returned when <code>#build()</code> is called.
 */
public abstract class AbstractDOMBuilder<T> {

    private Document localDoc;

    /**
     * Instructs the build to construct the object.
     * 
     * @return The constructed instance.
     * @throws ModelException
     *             Thrown if the build process fails.
     */
    public abstract T build() throws ModelException;

    /**
     * Add a NameSpace attribute to the supplied <code>Element</code>.
     * 
     * @param element
     *            The <code>Element</code> to modify.
     * @param ns
     *            The name space short name.<br />
     *            When added, that value will be prefixed with <i>xmlns:</i>.
     * @param schema
     *            The schema location of the NameSpace.
     */
    protected final void addNS(Element element, String ns, String schema) {
        element.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + ns, schema);
    }

    protected Document createDocument() {
        validateBeforeBuild();

        // Store in class to temporary use.
        localDoc = XmlUtil.createEmptyDocument();

        Element root = createRoot(localDoc);
        addRootAttributes(root);
        localDoc.appendChild(root);
        appendToRoot(localDoc, root);

        Document result = localDoc;
        localDoc = null;

        return result;
    }

    protected abstract Element createRoot(Document doc);

    /**
     * Method called by {@link #createDocument()}.<br />
     * Use this method to add additional NameSpace declarations to the <code>Document</code> or attributes to the root element.
     *
     * @param root
     *            The envelope <code>Element</code> instance.
     */
    protected abstract void addRootAttributes(Element root);

    protected abstract void appendToRoot(Document localDoc, Element root);

    protected Element createElement(Tag tag) {
        return localDoc.createElementNS(tag.getNS(), tag.getPrefix() + ":" + tag.getTagName());
    }

    /**
     * Validate the value of the attribute.<br />
     * This method is a simple validator, that only checks for <code>null</code> values.
     * 
     * @param attribute
     *            The name of the attribute being validated.<br />
     *            This value is used for providing an informative exception cause.
     * @param value
     *            The value to validate.
     * @throws ModelException
     *             Thrown if the value fails validation.
     */
    protected final void validate(String attribute, Object value) throws ModelException {
        if(value == null) {
            throw new ModelException(attribute + " is mandatory - but was null.");
        }
    }

    /**
     * Validate an attribute. <br />
     * This method validates that a <code>String</code> attribute is neither <code>null</code>, an empty <code>String</code> or a <code>String</code> of spaces.
     * 
     * @param attribute
     *            The name of the attribute being validated.<br />
     *            This value is used for providing an informative exception cause.
     * @param value
     *            The value to validate.
     * @throws ModelException
     *             Thrown if the value fails validation.
     */
    protected final void validate(String attribute, String value) throws ModelException {
        if(value == null) {
            throw new ModelException(attribute + " is mandatory - but was null.");
        }
        validateValue(attribute, value);
    }

    /**
     * Methdo called by {@link #createDocument()} before the process of creating the <code>Document</code> is initiated.<br />
     * Implementers can use the method to verify that all mandatory attriutes are set before constructing the <code>Document</code>.
     * 
     * @throws ModelException
     *             Thrown if one or more requirements are not fulfilled.
     */
    protected abstract void validateBeforeBuild() throws ModelException;

    /**
     * Validate the value of an attribute. <br />
     * This method validates that a <code>String</code> attribute is neither an empty <code>String</code> or a <code>String</code> of spaces.
     * 
     * @param attribute
     *            The name of the attribute being validated.<br />
     *            This value is used for providing an informative exception cause.
     * @param value
     *            The value to validate - if <code>null</code> the validation will be skipped.
     * @throws ModelException
     *             Thrown if the value fails validation.
     */
    protected final void validateValue(String attribute, String value) throws ModelException {
        if(value != null) {
            if(value.length() == 0) {
                throw new ModelException(attribute + " is mandatory - but was an empty String.");
            } else if(value.charAt(0) == ' ' || value.charAt(value.length() - 1) == ' ') {
                if(value.trim().length() == 0) {
                    throw new ModelException(attribute + " is mandatory - but was an empty String.");
                }
            }
        }
    }
}