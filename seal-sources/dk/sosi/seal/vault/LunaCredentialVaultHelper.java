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

/**
 * Helper interface used for wrapping all Luna code into a helper class.
 *
 * @author ads
 * @author $LastChangedBy: ads@lakeside.dk $
 * @since 2.0
 */
/* pp */interface LunaCredentialVaultHelper {

    /**
     * Retrieve a new instance of the <code>KeyStore</code>.
     *
     * @return
     */
    public KeyStore getKeyStore();

    /**
     * Initializes the <code>LunaCredentialVaultHelper</code>.
     *
     * @param properties
     *            <code>Properties</code> containing settings for the <code>LunaCredentialVaultHelper</code>.<br />
     *            For specific requirements see the actual implementation.
     */
    public void initialize(Properties properties);

    /**
     * Forces the <code>LunaCredentialVaultHelper</code> to logout from the Luna box.
     */
    public void logout();

    /**
     * If an operation fails
     */
    public void reinitialize();
}