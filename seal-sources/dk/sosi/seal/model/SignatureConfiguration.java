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


import org.w3c.dom.Node;

/**
 *
 * A simple class holding configuration parameters when generating XML signatures using @link{SignatureUtil}
 *
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class SignatureConfiguration {

    static enum Type { DIRECT_REFERENCE_NOT_ENVELOPED, DIRECT_REFERENCE, SECURITY_TOKEN_REFERENCE}

    static class Reference {

        private final String uri;
        private final Type type;

        public Reference(String uri, Type type) {
            this.uri = uri;
            this.type = type;
        }

        private static Reference[] fromDirectReferenceStringArray(String[] referenceURIs) {
            Reference[] references = new Reference[referenceURIs.length];
            for (int i = 0; i < referenceURIs.length; i++) {
                references[i] = new Reference(referenceURIs[i], Type.DIRECT_REFERENCE);
            }
            return references;
        }

        public String getURI() {
            return uri;
        }

        public Type getType() {
            return type;
        }
    }

    private final Reference[] references;
    private final String signatureParentID;
    private final String idAttributeName;

    private boolean addCertAsRef;
    private Node signatureSiblingNode;
    private String keyInfoId;

    public SignatureConfiguration(Reference[] references, String signatureParentID, String idAttributeName) {
        this.references = references;
        this.signatureParentID = signatureParentID;
        this.idAttributeName = idAttributeName;
        this.addCertAsRef = false;
    }

    public SignatureConfiguration(String[] referenceURIs, String signatureParentID, String idAttributeName) {
        this(Reference.fromDirectReferenceStringArray(referenceURIs), signatureParentID, idAttributeName);
    }

    public void setAddCertificateAsReference(boolean addCertAsRef) {
        this.addCertAsRef = addCertAsRef;
    }

    public void setSignatureSiblingNode(Node signatureSiblingNode) {
        this.signatureSiblingNode = signatureSiblingNode;
    }

    public void setKeyInfoId(String keyInfoId) {
        this.keyInfoId = keyInfoId;
    }

    public Reference[] getReferences() {
        return references;
    }

    public String getSignatureParentID() {
        return signatureParentID;
    }

    public boolean isAddCertificateAsReference() {
        return addCertAsRef;
    }

    public Node getSignatureSiblingNode() {
        return signatureSiblingNode;
    }

    public String getIdAttributeName() {
        return idAttributeName;
    }

    public String getKeyInfoId() {
        return keyInfoId;
    }
}
