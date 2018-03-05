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

package dk.sosi.seal;

import com.chrysalisits.crypto.LunaTokenManager;
import dk.sosi.seal.vault.CredentialVault;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Helper class used for test cases backed by the luna box.
 * 
 * @author ads
 */
public class LunaTestHelper {

    // Test password used SignaturGruppens Luna box - can only be used in known environments.
    // Public IP must be known by SignaturGruppen
    // public static final String PWD = "L5sC-W7s7-WANS-6ACT";
    public static final String PWD = "Ys5K-WX49-dtLL-WJ9/";

    public static void addCertificate(X509Certificate certificate) throws KeyStoreException {
        LunaTokenManager tokenManager = LunaTokenManager.getInstance();
        tokenManager.Login("L5sC-W7s7-WANS-6ACT");

        KeyStore lunaKS = KeyStore.getInstance("Luna");
        try {
            lunaKS.load(null, null);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        } catch (CertificateException e) {
            throw new KeyStoreException(e);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }
        
        lunaKS.setCertificateEntry(CredentialVault.ALIAS_SYSTEM, certificate);
//        tokenManager.Logout();
    }
}
