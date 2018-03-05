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

import dk.sosi.seal.model.constants.Tag;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.*;

import java.util.*;

/**
 * Abstract class used by classes directly modifying an underlying DOM model object.
 * 
 * @author ads
 */
public abstract class AbstractDOMInfoExtractor {

    /** The underlying DOM representation */
    protected final Element dom;
    private Map<String, String> namespaces;

    public AbstractDOMInfoExtractor(Element dom) {
        if (dom == null) {
            throw new IllegalArgumentException("Element cannot be null");
        }
        this.dom = dom;
    }

    public AbstractDOMInfoExtractor(Document doc) {
        if (doc == null) {
            throw new IllegalArgumentException("Document cannot be null");
        }
        this.dom = doc.getDocumentElement();
    }

    /**
     * Converts the attribute of the supplied <code>Element</code> to a <code>Date</code> using <code>XMLUtil.getDateFormat(true)...</code>.
     * 
     * @param element
     *            The <code>Element</code> to retrieve the attribute from.
     * @param attribute
     *            The name of the attribute to convert.
     * @return The converted <code>Date</code> object.
     */
    protected Date convertToDate(Element element, String attribute) {
        if (element == null) {
            throw new ModelException("Date element cannot be null");
        }
        String value;
        if(attribute != null) {
            value = element.getAttribute(attribute);
        } else {
            value = element.getTextContent();
        }

        try {
            return XmlUtil.parseZuluDateTime(value);
        } catch (ModelException e) {
            throw new ModelException("Invalid date format of " + (attribute != null ? attribute : "text contents") + " (" + value + ")", e);
        }
    }

    /**
     * Filter the supplied <code>NodeList</code> and retrieve the <code>Element</code> having the supplied attribute matching the supplied value.<br />
     * 
     * @param nl
     *            The <code>NodeList</code> to filter.
     * @param attribute
     *            The attribute to test.
     * @param value
     *            The value to filter for.
     * @return The matching <code>Element</code> or <code>null</code> if no match was found.
     */
    protected Element getFilteredElement(List<Element> nl, String attribute, String value) {
        for (Element tmp : nl) {
            String val = tmp.getAttribute(attribute);
            if (val != null) {
                if (val.equals(value)) {
                    return tmp;
                }
            }
        }
        return null;
    }

    /**
     * Retrieve the <code>Element</code> identified by the supplied tag path structure.<br />
     * This method will traverse the DOM retrieve the first child for each specified tag.
     * 
     * @param tags
     *            List of tag names to traverse.
     * @return The <code>Element</code> matching the final tag in the list.
     */
    protected Element getTag(Tag... tags) {
        return getTag(dom, tags);
    }

    protected Element getTag(Element elm, Tag... tags) {
        if(tags.length == 1) {
            return elm;
        }
        return getFirstElement(getTags(elm, tags));
    }

    /**
     * Retrieve the <code>NodeList</code> identified by the supplied tag path structure.<br />
     * This method will traverse the DOM retrieve the first child for each specified tag.
     * 
     * @param tags
     *            List of tag names to traverse.
     * @return The <code>NodeList</code> matching the final tag in the list.
     */
    protected List<Element> getTags(Tag... tags) {
        return getTags(dom, tags);
    }

    protected List<Element> getTags(Element elm, Tag... tags) {
        for (int i = 1; i < tags.length - 1; i++) {
            Tag tag = tags[i];
            elm = getFirstElement(getElements(elm, tag, true));
        }

        Tag tag = tags[tags.length - 1];
        return getElements(elm, tag, false);
    }

    private List<Element> getElements(Element elm, Tag tag, boolean onlyFirst) {
        List<Element> res = new ArrayList<Element>();

        if (elm == null) {
             return res;
        }

        NodeList childNodes = elm.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node childNode = childNodes.item(i);
            if(childNode instanceof Element) {
                Element childElm = (Element)childNode;
                if(matches(childElm, tag)) {
                    res.add(childElm);
                    if(onlyFirst) {
                        break;
                    }
                }
            }
        }
        return res;
    }

    private boolean matches(Element childElm, Tag tag) {
        if(childElm.getLocalName() != null) {
            if(childElm.getNamespaceURI() != null) {
                return childElm.getNamespaceURI().equals(tag.getNS()) && tag.getTagName().equals(childElm.getLocalName());
            }
            return tag.getTagName().equals(childElm.getLocalName());
        }

        String tn = childElm.getTagName();
        int colonIndex = tn.indexOf(':');

        if(colonIndex == -1) {
            return tag.getNS() == null && tag.getTagName().equals(tn);
        }

        String nsPrefix = getNamesSpaces().get(tag.getNS());
        return childElm.getTagName().equals(nsPrefix + ":" + tag.getTagName());
    }

    protected String safeGetTagTextContent(Tag... tags) {
        Element element = getTag(tags);
        return element != null ? element.getTextContent() : null;
    }

    protected String safeGetAttribute( String attributeName, Tag... tags) {
        Element element = getTag(tags);
        return element != null ? element.getAttribute(attributeName) : null;
    }

    private Map<String, String> getNamesSpaces() {
        if(namespaces == null) {
            namespaces = new HashMap<String, String>();

            NamedNodeMap attributes = dom.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Attr attribute = (Attr)attributes.item(i);

                String name = attribute.getName();
                String value = attribute.getValue();

                if(name.startsWith("xmlns:")) {
                    namespaces.put(value, name.substring("xmlns:".length()));
                }
            }
        }
        return namespaces;
    }

    private Element getFirstElement(List<Element> nodeList) {
        if(nodeList.isEmpty()) {
            return null;
        }
        return nodeList.get(0);
    }
}