/*
 * Copyright (C) 2007-2022 Crafter Software Corporation. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jenkinsci.plugins.scriptsecurity.sandbox.blacklists;

import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Extension of {@link StaticWhitelist} that works as a blacklist by negating all operations
 *
 * @author joseross
 */
public class Blacklist extends StaticWhitelist {

    public Blacklist(Reader definition) throws IOException {
        super(definition);
    }

    @Override
    public boolean permitsMethod(Method method, Object receiver, Object[] args) {
        return !super.permitsMethod(method, receiver, args);
    }

    @Override
    public boolean permitsConstructor(Constructor<?> constructor, Object[] args) {
        return !super.permitsConstructor(constructor, args);
    }

    @Override
    public boolean permitsStaticMethod(Method method, Object[] args) {
        return !super.permitsStaticMethod(method, args);
    }

    @Override
    public boolean permitsFieldGet(Field field, Object receiver) {
        return !super.permitsFieldGet(field, receiver);
    }

    @Override
    public boolean permitsFieldSet(Field field, Object receiver, Object value) {
        return super.permitsFieldSet(field, receiver, value);
    }

    @Override
    public boolean permitsStaticFieldGet(Field field) {
        return !super.permitsStaticFieldGet(field);
    }

    @Override
    public boolean permitsStaticFieldSet(Field field, Object value) {
        return super.permitsStaticFieldSet(field, value);
    }

}
