/*
 * Copyright (C) 2007-2025 Crafter Software Corporation. All Rights Reserved.
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
package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Objects;

import static java.util.Collections.unmodifiableCollection;
import static org.apache.commons.collections4.CollectionUtils.isEmpty;

/**
 * Composite of multiple whitelists
 * A call is permitted if all delegates permit it
 */
public class CompositeWhitelist extends Whitelist {
	protected final Collection<? extends Whitelist> delegates;

	public CompositeWhitelist(final Collection<? extends Whitelist> delegates) {
		if (isEmpty(delegates)) {
			throw new IllegalArgumentException("delegates must not be empty");
		}
		if (delegates.stream().anyMatch(Objects::isNull)) {
			throw new IllegalArgumentException("delegates must not contain null elements");
		}
		this.delegates = unmodifiableCollection(delegates);
	}

	@Override
	public boolean permitsMethod(@Nonnull Method method, @Nonnull Object receiver, @Nonnull Object... args) {
		return delegates.stream().allMatch(delegate -> delegate.permitsMethod(method, receiver, args));
	}

	@Override
	public boolean permitsConstructor(@Nonnull Constructor<?> constructor, @Nonnull Object... args) {
		return delegates.stream().allMatch(delegate -> delegate.permitsConstructor(constructor, args));
	}

	@Override
	public boolean permitsStaticMethod(@Nonnull Method method, @Nonnull Object... args) {
		return delegates.stream().allMatch(delegate -> delegate.permitsStaticMethod(method, args));
	}

	@Override
	public boolean permitsFieldGet(@Nonnull Field field, @Nonnull Object receiver) {
		return delegates.stream().allMatch(delegate -> delegate.permitsFieldGet(field, receiver));
	}

	@Override
	public boolean permitsFieldSet(@Nonnull Field field, @Nonnull Object receiver, @CheckForNull Object value) {
		return delegates.stream().allMatch(delegate -> delegate.permitsFieldSet(field, receiver, value));
	}

	@Override
	public boolean permitsStaticFieldGet(@Nonnull Field field) {
		return delegates.stream().allMatch(delegate -> delegate.permitsStaticFieldGet(field));
	}

	@Override
	public boolean permitsStaticFieldSet(@Nonnull Field field, @CheckForNull Object value) {
		return delegates.stream().allMatch(delegate -> delegate.permitsStaticFieldSet(field, value));
	}

	@Override
	public boolean isAllowedGetEnvSystemMethod(@Nonnull Method m, @Nonnull Object[] args) {
		return delegates.stream().allMatch(delegate -> delegate.isAllowedGetEnvSystemMethod(m, args));
	}
}
