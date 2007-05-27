/****************************************************************************
 * Copyright (c) 2004 Composent, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Composent, Inc. - initial API and implementation
 *****************************************************************************/

package org.eclipse.ecf.ui.util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.core.runtime.Assert;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.Platform;
import org.eclipse.ecf.internal.ui.Activator;

/**
 * Helper for caching password via
 * {@link Platform#addAuthorizationInfo(URL, String, String, Map)}
 */
public class PasswordCacheHelper {

	public static final URL FAKE_URL;
	public static final String AUTH_SCHEME = ""; //$NON-NLS-1$
	public static final String INFO_PASSWORD = "org.eclipse.ecf.ui.password"; //$NON-NLS-1$
	private String targetAuthority;

	static {
		URL temp = null;
		try {
			temp = new URL("http://org.eclipse.ecf.ui"); //$NON-NLS-1$
		} catch (MalformedURLException e) {
			// Never happens
		}
		FAKE_URL = temp;
	}

	public PasswordCacheHelper(String targetID) {
		this.targetAuthority = targetID;
		Assert.isNotNull(this.targetAuthority);
	}

	public boolean savePassword(String password) {
		Map map = Platform.getAuthorizationInfo(FAKE_URL, targetAuthority,
				AUTH_SCHEME);
		if (map == null) {
			map = new HashMap(10);
		}
		if (password != null)
			map.put(INFO_PASSWORD, password);

		try {
			Platform.addAuthorizationInfo(FAKE_URL, targetAuthority,
					AUTH_SCHEME, map);
		} catch (CoreException e) {
			Activator.log("savePassword", e); //$NON-NLS-1$
			return false;
		}
		return true;
	}

	public String retrievePassword() {
		Map map = Platform.getAuthorizationInfo(FAKE_URL, targetAuthority,
				AUTH_SCHEME);
		if (map != null) {
			return (String) map.get(INFO_PASSWORD);
		}
		return null;
	}
}
