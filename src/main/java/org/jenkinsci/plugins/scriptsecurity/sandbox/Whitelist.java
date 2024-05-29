/*
 * The MIT License
 *
 * Copyright 2014 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.scriptsecurity.sandbox;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import static java.lang.reflect.Modifier.isStatic;

/**
 * Determines which methods and similar members which scripts may call.
 */
public abstract class Whitelist {

    private List<String> getEnvWhitelistRegex = new ArrayList<>();

    public void setGetEnvWhitelistRegex(List<String> getEnvWhitelistRegex) {
        this.getEnvWhitelistRegex = getEnvWhitelistRegex;
    }

    /**
     * Return true if the given method is allowed System.getEnv()
     * @param m the method
     * @param args the method arguments
     * @return true if allowed, false otherwise
     */
    public boolean isAllowedGetEnvSystemMethod(@Nonnull Method m, @Nonnull Object[] args) {
        // Check if the method is "getenv" and it's a static method in the System class
        if ("getenv".equals(m.getName()) &&
                isStatic(m.getModifiers()) &&
                m.getDeclaringClass().equals(System.class) &&
                args.length == 1 && args[0] instanceof String) {
            String envName = (String) args[0];
            // Match the envName against the regex
            for (String regex : getEnvWhitelistRegex) {
                if (Pattern.matches(regex, envName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks whether a given virtual method may be invoked.
     * <p>Note that {@code method} should not be implementing or overriding a method in a supertype;
     * in such a case the caller must pass that supertype method instead.
     * In other words, call site selection is the responsibility of the caller (such as {@code GroovySandbox}), not the whitelist.
     * @param method a method defined in the JVM
     * @param receiver {@code this}, the receiver of the method call
     * @param args zero or more arguments
     * @return true to allow the method to be called, false to reject it
     */
    public abstract boolean permitsMethod(@Nonnull Method method, @Nonnull Object receiver, @Nonnull Object[] args);

    public abstract boolean permitsConstructor(@Nonnull Constructor<?> constructor, @Nonnull Object[] args);

    public abstract boolean permitsStaticMethod(@Nonnull Method method, @Nonnull Object[] args);

    public abstract boolean permitsFieldGet(@Nonnull Field field, @Nonnull Object receiver);

    public abstract boolean permitsFieldSet(@Nonnull Field field, @Nonnull Object receiver, @CheckForNull Object value);

    public abstract boolean permitsStaticFieldGet(@Nonnull Field field);

    public abstract boolean permitsStaticFieldSet(@Nonnull Field field, @CheckForNull Object value);

}
