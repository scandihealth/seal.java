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
package dk.sosi.seal.model;

import org.jdom.Attribute;
import org.jdom.Element;
import org.jdom.Namespace;
import org.jdom.input.SAXBuilder;

import java.io.StringReader;
import java.util.Iterator;
import java.util.List;

import static junit.framework.Assert.assertTrue;

public abstract class XMLValidator {

    public void assertXML(String xml, String fileContainingExpectedResult) throws Exception {
        SAXBuilder builder = new SAXBuilder();

        org.jdom.Document actualDoc = builder.build(new StringReader(xml));
        org.jdom.Document excepectedDoc = builder.build(getClass().getResource("/idwsh-examples/" + fileContainingExpectedResult));

        assertTrue("Validation failed - see log", assertElements(actualDoc.getRootElement(), excepectedDoc.getRootElement()));
    }

    /**
     * Override this method to handle attribute validation.
     * 
     * @param element
     *            The element.
     * @param attribute
     *            The attribute on the element.
     * @param expectedValue
     *            The expected value.
     * @param actualValue
     *            The actual value.
     * @return <code>true</code> if valid - otherwise <code>false</code>.
     */
    protected boolean assertAttributeValues(Element element, Attribute attribute, String expectedValue, String actualValue) {
        if(!expectedValue.equals(actualValue)) {
            return err(element.getName(), attribute.getName(), "Incorrect value of (" + element.getName() + "#" + attribute.getName() + ") - Expected: " + expectedValue + ", Actual: " + actualValue);
        }
        return true;
    }

    protected boolean assertTextContent(Element element, String expectedContents, String actualContents) {
        if(!expectedContents.equals(actualContents)) {
            return err(element.getName(), null, "Content of (" + element.getName() + ") not equals - expected (" + expectedContents + ") actual (" + actualContents + ")");
        }
        return true;
    }

    protected boolean ignore(String tag, String attribute) {
        return false;
    }

    @SuppressWarnings("unchecked")
    private boolean assertElements(Element actualElm, Element expectedElm) {
        boolean res = assertTagsAndAttributes(actualElm, expectedElm);

        List<Element> expectedChildren = expectedElm.getChildren();
        for (Iterator<Element> iterator = expectedChildren.iterator(); iterator.hasNext();) {
            Element expectedChildElement = iterator.next();
            Element actualChildElement = actualElm.getChild(expectedChildElement.getName(), expectedChildElement.getNamespace());

            if(actualChildElement == null) {
                res = err(expectedChildElement.getName(), null, "Child element (" + expectedChildElement.getName() + ") not found under (" + actualElm.getName() + ")");
                continue;
            }

            res &= assertElements(actualChildElement, expectedChildElement);

            actualElm.removeContent(actualChildElement);
        }

        if(!actualElm.getChildren().isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Remaining children in (" + actualElm.getName() + ") (" + actualElm.getChildren().size() + ") [");
            for (Iterator<Element> iterator = actualElm.getChildren().iterator(); iterator.hasNext();) {
                Element element = iterator.next();
                sb.append(element.getName()).append(", ");
            }
            sb.append("]");

            res = err(actualElm.getName(), null, sb.toString());
        } else {
            String expectedContents = expectedElm.getText().trim();
            String actualContents = actualElm.getText().trim();

            res &= assertTextContent(expectedElm, expectedContents, actualContents);
        }

        return res;
    }

    @SuppressWarnings("unchecked")
    private boolean assertTagsAndAttributes(Element actualElm, Element expectedElm) {
        boolean res = true;

        String expectedTagName = expectedElm.getName();
        String actualTagName = actualElm.getName();
        if(!expectedTagName.equals(actualTagName)) {
            res = err(expectedTagName, null, "Tag names incorrect - expected (" + expectedTagName + "), actual (" + actualTagName + ")");
        }

        Namespace expectedNS = expectedElm.getNamespace();
        Namespace actualNS = actualElm.getNamespace();
        if(!expectedNS.equals(actualNS)) {
            res = err(expectedTagName, null, "Tag namepace incorrect - expected (" + expectedNS + "), actual (" + actualNS + ")");
        }

        List<Attribute> actualAttributes = actualElm.getAttributes();
        List<Attribute> expectedAttributes = expectedElm.getAttributes();

        if(actualAttributes.isEmpty() && expectedAttributes.isEmpty()) {
            return res;
        }

        if(actualAttributes.size() != expectedAttributes.size()) {
            res = err(expectedTagName, null, "Expected number of attributes on (" + expectedTagName + ") is (" + expectedAttributes.size() + ") but was (" + actualAttributes.size() + ")");
        }

        for (Iterator<Attribute> iterator = expectedAttributes.iterator(); iterator.hasNext();) {
            Attribute expectedAttribute = iterator.next();
            Attribute actualAttribute;
            if("".equals(expectedAttribute.getNamespace().getPrefix())) {
                actualAttribute = actualElm.getAttribute(expectedAttribute.getName());
            } else {
                actualAttribute = actualElm.getAttribute(expectedAttribute.getName(), expectedAttribute.getNamespace());
            }

            if(actualAttribute == null) {
                res = err(expectedElm.getName(), expectedAttribute.getName(), "Expected attribute is missing (" + expectedElm.getName() + "#" + expectedAttribute.getName() + ") - expected (" + expectedAttribute.getName() + " = " + expectedAttribute.getValue() + ")");
                continue;
            }
            actualElm.removeAttribute(actualAttribute); // Remove from DOM - used to track of the DOM contain unexpected attributes.

            String expectedValue = expectedAttribute.getValue();
            String actualValue = actualAttribute.getValue();

            res &= assertAttributeValues(expectedElm, expectedAttribute, expectedValue, actualValue);
        }

        if(!actualElm.getAttributes().isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Element (" + expectedElm.getName() + ") contains unknown attributes [");

            List<Attribute> attributes = actualElm.getAttributes();
            for (Attribute attribute : attributes) {
                sb.append(attribute.getName()).append(", ");
            }
            sb.append("]");

            res = err(expectedElm.getName(), null, sb.toString());
        }

        return res;
    }

    private boolean err(String tag, String attribute, String message) {
        if(!ignore(tag, attribute)) {
            System.err.println("VALIDATION FAIL: " + message);
            return false;
        }
        return true;
    }
}
