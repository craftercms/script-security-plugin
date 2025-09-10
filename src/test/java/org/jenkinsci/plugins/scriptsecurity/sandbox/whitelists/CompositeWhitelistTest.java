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

import groovy.lang.Binding;
import groovy.lang.GroovyClassLoader;
import groovy.util.GroovyScriptEngine;
import groovy.util.ResourceException;
import groovy.util.ScriptException;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.blacklists.Blacklist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxInterceptor;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.groovy.sandbox.SandboxTransformer;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.io.InputStreamReader;

import static java.util.List.of;
import static org.junit.Assert.assertThrows;

@RunWith(MockitoJUnitRunner.class)
public class CompositeWhitelistTest {

	private static final String EMPTY_WHITELIST = "groovy/whitelist-empty";
	private static final String WHITELIST = "groovy/whitelist";
	private static final String BLACKLIST = "groovy/blacklist";
	private static final String SCRIPTS_PATH = "src/test/resources/groovy/scripts";

	private static final String INVALID_SCRIPT = "invalid.groovy";
	private static final String MULTIPLE_OPS_SCRIPT = "multiple-ops.groovy";

	private GroovyScriptEngine scriptEngine;
	private SandboxInterceptor sandboxInterceptorEmptyWhitelist;
	private SandboxInterceptor sandboxInterceptor;

	@Before
	public void setup() throws IOException {
		scriptEngine = setUpGroovyScriptEngine();
		sandboxInterceptorEmptyWhitelist = setUpSandboxInterceptor(EMPTY_WHITELIST);
		sandboxInterceptor = setUpSandboxInterceptor(WHITELIST);
	}

	@Test
	public void testRestrictedCall() {
		sandboxInterceptorEmptyWhitelist.register();

		assertThrows(INVALID_SCRIPT + " contains unsupported operations", UnsupportedOperationException.class, () ->
				scriptEngine.run(INVALID_SCRIPT, new Binding()));

		sandboxInterceptorEmptyWhitelist.unregister();
	}

	@Test
	public void testAllowedCall() throws ScriptException, ResourceException {
		sandboxInterceptor.register();
		scriptEngine.run(INVALID_SCRIPT, new Binding());

		sandboxInterceptor.unregister();
	}

	@Test
	public void testMultipleRestrictedCalls() {
		sandboxInterceptorEmptyWhitelist.register();
		assertThrows(MULTIPLE_OPS_SCRIPT + " contains unsupported operations", UnsupportedOperationException.class, () ->
				scriptEngine.run(MULTIPLE_OPS_SCRIPT, new Binding()));
		sandboxInterceptorEmptyWhitelist.unregister();

		sandboxInterceptor.register();
		assertThrows(MULTIPLE_OPS_SCRIPT + " contains non-whitelisted operations. They should fail even if accepted" +
				" by the blacklist", UnsupportedOperationException.class, () ->
				scriptEngine.run(MULTIPLE_OPS_SCRIPT, new Binding()));
		sandboxInterceptor.unregister();
	}

	protected GroovyScriptEngine setUpGroovyScriptEngine() throws IOException {
		CompilerConfiguration compilerConfig = new CompilerConfiguration();
		compilerConfig.addCompilationCustomizers(new SandboxTransformer());
		return new GroovyScriptEngine(SCRIPTS_PATH,
				new GroovyClassLoader(getClass().getClassLoader(), compilerConfig));
	}

	@SuppressWarnings("ConstantConditions")
	protected SandboxInterceptor setUpSandboxInterceptor(String whitelist) throws IOException {
		ClassLoader loader = getClass().getClassLoader();
		Whitelist whitelist1 = new Blacklist(new InputStreamReader(loader.getResourceAsStream(BLACKLIST)));
		Whitelist whitelist2 = new StaticWhitelist(new InputStreamReader(loader.getResourceAsStream(whitelist)));

		return new SandboxInterceptor(new CompositeWhitelist(of(whitelist1, whitelist2)));
	}
}
