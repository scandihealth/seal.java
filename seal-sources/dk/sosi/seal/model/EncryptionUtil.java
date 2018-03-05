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

import dk.sosi.seal.xml.XmlUtil;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class EncryptionUtil {

    public static final String ENCRYPTION_ALGORITHM = "AES";
    public static final int ENCRYPTION_KEY_SIZE = 128;

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * The supplied element is encrypted
     *
     * @param element
     * @param key
     */
    public static void encrypt(Element element, PublicKey key) {
        try {
            Key symmetricKey = generateDataEncryptionKey();
            Key keyEncryptingKey = key;

            XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            keyCipher.init(XMLCipher.WRAP_MODE, keyEncryptingKey);
            EncryptedKey encryptedKey = keyCipher.encryptKey(element.getOwnerDocument(), symmetricKey);

            XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
            xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

            EncryptedData encryptedData = xmlCipher.getEncryptedData();
            KeyInfo keyInfo = new KeyInfo(element.getOwnerDocument());
            keyInfo.add(encryptedKey);
            encryptedData.setKeyInfo(keyInfo);

            xmlCipher.doFinal(element.getOwnerDocument(), element);

        } catch (Exception e) { // xmlCipher.doFinal can throw a raw Exception, so we need to catch it like this :(
            throw new ModelException("Unable to encrypt element", e);
        }
    }

    /**
     * Decrypts the element with the supplied key
     *
     * @param element
     * @param key
     */
    public static void decrypt(Element element, PrivateKey key) {
        try {
            XMLCipher xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
            xmlCipher.setKEK(key);
            xmlCipher.doFinal(element.getOwnerDocument(), element);
        } catch (Exception e) { // xmlCipher.doFinal can throw a raw Exception, so we need to catch it like this :(
            throw new ModelException("Unable to decrypt element", e);
        }

    }
    /**
     * Decrypts the element with the supplied key
     *
     * @param element
     * @param key
     */
    public static Element decryptAndDetach(Element element, PrivateKey key) {
        Document doc = XmlUtil.createEmptyDocument();
        Element importedElement = (Element) doc.importNode(element, true);
        doc.appendChild(importedElement);
        decrypt(importedElement, key);
        Element assertion = doc.getDocumentElement();
        return assertion;
    }

    private static SecretKey generateDataEncryptionKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        keyGenerator.init(ENCRYPTION_KEY_SIZE);
        return keyGenerator.generateKey();
    }

}
