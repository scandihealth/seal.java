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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/AuthenticationLevel.java $
 * $Id: AuthenticationLevel.java 10349 2012-10-19 08:38:16Z ChristianGasser $
 */

package dk.sosi.seal.model;

import java.io.Serializable;

/**
 * Enumeration class for authentication levels.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class AuthenticationLevel  implements Serializable { // NOPMD
	private static final long serialVersionUID = -1620977755942090763L;

	public static final AuthenticationLevel NO_AUTHENTICATION = new AuthenticationLevel(1);
	public static final AuthenticationLevel USERNAME_PASSWORD_AUTHENTICATION = new AuthenticationLevel(2);
	public static final AuthenticationLevel VOCES_TRUSTED_SYSTEM = new AuthenticationLevel(3);
	public static final AuthenticationLevel MOCES_TRUSTED_USER = new AuthenticationLevel(4);

	private final int level;

	private AuthenticationLevel(int level) { // Prevent instantiation

		this.level = level;
	}

	/**
	 * Returns the authentication level corresponding to a enumerated value
	 */
	public int getLevel() {

		return level;
	}

	/**
	 * Returns the enumerated value corresponding to the passed authentication
	 * level
	 *
	 * @param authLevel
	 *            the authentication level
	 */
	public static AuthenticationLevel getEnumeratedValue(int authLevel) {
		AuthenticationLevel result;
		switch (authLevel) {
		case 1:
			result = NO_AUTHENTICATION;
			break;
		case 2:
			result = USERNAME_PASSWORD_AUTHENTICATION;
			break;
		case 3:
			result = VOCES_TRUSTED_SYSTEM; // NOPMD
			break;
		case 4:
			result = MOCES_TRUSTED_USER; // NOPMD
			break;
		default:
			throw new ModelException("Authentication level presently not supported by SOSI");
		}
		return result;
	}

	public boolean equals(Object obj) {
		return obj == this || obj != null && obj.getClass() == getClass() && obj.hashCode() == hashCode()
		&& getLevel()==((AuthenticationLevel)obj).getLevel();
	}

	public int hashCode() {
		return getLevel();
	}
}
