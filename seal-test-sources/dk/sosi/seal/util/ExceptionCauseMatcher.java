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

package dk.sosi.seal.util;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class ExceptionCauseMatcher extends BaseMatcher {

    private Class<? extends Exception> expectedClass;

    public ExceptionCauseMatcher(Class<? extends Exception> expectedClass) {
        if (expectedClass == null) {
            throw new IllegalArgumentException("expectedClass cannot be null");
        }
        this.expectedClass = expectedClass;
    }

    public void describeTo(Description description) {
        description.appendText("Exception cause should be : " + expectedClass.toString());
    }

    public boolean matches(Object obj) {
        if (obj instanceof Exception == false) {
            return false;
        }
        Exception e = (Exception) obj;
        if (e.getCause() == null) {
            return false;
        }
        return expectedClass.equals(e.getCause().getClass());
    }
}