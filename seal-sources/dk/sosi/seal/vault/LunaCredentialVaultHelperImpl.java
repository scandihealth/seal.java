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

import com.chrysalisits.crypto.LunaAPI;
import com.chrysalisits.crypto.LunaCryptokiException;
import com.chrysalisits.crypto.LunaJCAProvider;
import com.chrysalisits.crypto.LunaTokenManager;
import com.chrysalisits.cryptox.LunaJCEProvider;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 * Default implementation of the <code>LunaCredentialVaultHelper</code> interface.
 *
 * All access to the underlying LunaTokenManager is synchronized
 *
 * @author ads
 * @author $LastChangedBy: ads@lakeside.dk $
 * @since 2.0
 */
/* pp */class LunaCredentialVaultHelperImpl implements LunaCredentialVaultHelper {

    private static final int USER_ROLE = 134217729;

    private String pwd;
    private int slot;

    private volatile boolean isReinitializing;

    public synchronized void initialize(Properties properties) {
        Security.addProvider(new LunaJCAProvider());
        Security.addProvider(new LunaJCEProvider());

        pwd = properties.getProperty(LunaCredentialVault.PROPERTYNAME_LUNA_CREDENTIAL_VAULT_PWD);
        slot = Integer.parseInt(properties.getProperty(LunaCredentialVault.PROPERTYNAME_LUNA_CREDENTIAL_VAULT_SLOT, "1"));
        if(pwd == null) {
            throw new IllegalArgumentException("Password not set. Password must be set through the property '" + LunaCredentialVault.PROPERTYNAME_LUNA_CREDENTIAL_VAULT_PWD + "'");
        }
        LunaTokenManager.getInstance().Login(slot, USER_ROLE, pwd);
    }

    public synchronized void logout() {
        LunaTokenManager.getInstance().Logout();
    }

    public synchronized KeyStore getKeyStore() {
        try {
            KeyStore lunaKS = KeyStore.getInstance("Luna");
            lunaKS.load(null, null);
            return lunaKS;
        } catch (KeyStoreException e) {
            throw new CredentialVaultException("Error during initialization of the Luna KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CredentialVaultException("Error during initialization of the Luna KeyStore", e);
        } catch (CertificateException e) {
            throw new CredentialVaultException("Error during initialization of the Luna KeyStore", e);
        } catch (IOException e) {
            throw new CredentialVaultException("Error during initialization of the Luna KeyStore", e);
        }
    }

    public void reinitialize() {
        if (!isReinitializing) {
            synchronized (this) {
                if (!isReinitializing) {
                    isReinitializing = true;
                    try {
                        LunaTokenManager.getInstance().Logout();
                        lunaReconnect();
                        LunaTokenManager.getInstance().Login(slot, USER_ROLE, pwd);
                    } finally {
                        isReinitializing = false;
                    }
                }
            }
        } else {
            //Wait until re-initializing is completed by the other thread
            synchronized (this) {
                return;
            }
        }
    }

    private boolean lunaReconnect() {
        // call static private method: LunaSession.CloseAllOpenSessions();
        try {
            Class<?> c = Class.forName("com.chrysalisits.crypto.LunaSession");
            java.lang.reflect.Method m = c.getDeclaredMethod("CloseAllOpenSessions");
            m.setAccessible(true);
            m.invoke(null);
        } catch (Exception ex) {
            // something is very wrong - stop the program and debug
            throw new RuntimeException(ex);
        }

        // attempt to close the existing NTLA connection (if any - might throw exception)
        LunaAPI lunaAPI = LunaTokenManager.getInstance().GetLunaAPI();
        try {
            lunaAPI.Finalize();
        } catch (Exception ex) {
            // not really an important error, ignore it
        }

        // re-open the connection
        try {
            lunaAPI.Initialize();
        } catch (LunaCryptokiException ex) {
            return false;
        }
        return true;
    }
}