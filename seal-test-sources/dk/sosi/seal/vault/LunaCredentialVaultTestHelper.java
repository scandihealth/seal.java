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

package dk.sosi.seal.vault;

import java.security.KeyStore;
import java.util.Properties;

public class LunaCredentialVaultTestHelper implements LunaCredentialVaultHelper {

    static int getKeyStoreCount = 0;
    static int initializeCount = 0;
    static int logoutCount = 0;
    static int reinitializeCount = 0;

    public static void reset() {
        getKeyStoreCount = 0;
        initializeCount = 0;
        logoutCount = 0;
    }

    public KeyStore getKeyStore() {
        getKeyStoreCount++;
        return new KeyStore(null, null, null) {
            // Default impl - overridden to gain access to constructor.
        };
    }

    public void initialize(Properties properties) {
        initializeCount++;
    }

    public void logout() {
        logoutCount++;
    }

    public void reinitialize() {
        reinitializeCount++;
    }
}
