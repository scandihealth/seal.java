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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/testobjects/PrintStreamAdapter.java $
 * $Id: PrintStreamAdapter.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki.testobjects;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;

public class PrintStreamAdapter extends java.io.PrintStream {

    public StringBuffer sb = new StringBuffer();

    public PrintStreamAdapter() throws FileNotFoundException {
        super(new OutputStream() {
            public void write(int b) throws IOException {
                // do nothing
            }
        });
    }

    public boolean checkError() {
        return false;
    }

    public void close() {

    }

    public void flush() {
    }

    public void print(boolean x) {
        sb.append(x);
    }

    public void print(char x) {
        sb.append(x);
    }

    public void print(char[] x) {
        sb.append(x);
    }

    public void print(double x) {
        sb.append(x);
    }

    public void print(float x) {
        sb.append(x);
    }

    public void print(int x) {
        sb.append(x);
    }

    public void print(long x) {
        sb.append(x);
    }

    public void print(Object x) {
        sb.append(x);
    }

    public void print(String x) {
        sb.append(x);
    }

    public void println() {
        sb.append("\n");
    }

    public void println(boolean x) {
        sb.append(x);
    }

    public void println(char x) {
        sb.append(x);
    }

    public void println(char[] x) {
        sb.append(x);
    }

    public void println(double x) {
        sb.append(x);
    }

    public void println(float x) {
        sb.append(x);
    }

    public void println(int x) {
        sb.append(x);
    }

    public void println(long x) {
        sb.append(x);
    }

    public void println(Object x) {
        sb.append(x);
    }

    public void println(String x) {
        sb.append(x);
    }

    public void reset() {
        sb = new StringBuffer();
    }

    public void write(byte[] x, int y, int z) {
        sb.append(x);
    }

    public void write(int x) {
        sb.append(x);
    }
}
