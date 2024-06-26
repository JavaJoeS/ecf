/****************************************************************************
 * Copyright (c) 2004 Composent, Inc. and others.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * Contributors:
 *    Composent, Inc. - initial API and implementation
 *
 * SPDX-License-Identifier: EPL-2.0
 *****************************************************************************/
package org.eclipse.ecf.internal.example.collab.start;

import java.util.*;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.preferences.InstanceScope;
import org.eclipse.ecf.internal.example.collab.ClientPlugin;
import org.eclipse.ecf.internal.example.collab.Messages;
import org.osgi.service.prefs.BackingStoreException;
import org.osgi.service.prefs.Preferences;

public class AccountStart {
	private static final String SAVED = "saved-connections"; //$NON-NLS-1$
	private static final int BACKING_STORE_SAVE_ERROR = 1001;
	private static final int BACKING_STORE_LOAD_ERROR = 1002;
	private Map connectionDetails = new HashMap();

	public ConnectionDetails addConnectionDetails(ConnectionDetails cd) {
		String targetURI = normalizeURI(cd.getTargetURI());
		return (ConnectionDetails) connectionDetails.put(targetURI, cd);
	}

	private String normalizeURI(String uri) {
		return uri.replace('/', '.');
	}

	public void removeConnectionDetails(ConnectionDetails cd) {
		try {
			Preferences preferences = InstanceScope.INSTANCE.getNode(ClientPlugin.PLUGIN_ID);
			Preferences connections = preferences.node(SAVED);
			String[] targets = connections.childrenNames();
			for (int i = 0; i < targets.length; i++) {
				String target = targets[i];
				Preferences node = connections.node(target);
				String cdTarget = normalizeURI(cd.getTargetURI());
				if (node != null && target != null && target.equals(cdTarget)) {
					node.removeNode();
				}
			}
			connections.flush();
		} catch (BackingStoreException e) {
			ClientPlugin.getDefault().getLog().log(new Status(IStatus.ERROR, ClientPlugin.PLUGIN_ID, BACKING_STORE_LOAD_ERROR, Messages.AccountStart_EXCEPTION_LOADING_CONNECTION_DETAILS, e));
		}
	}

	public Collection getConnectionDetails() {
		return connectionDetails.values();
	}

	public void saveConnectionDetailsToPreferenceStore() {
		Preferences preferences = InstanceScope.INSTANCE.getNode(ClientPlugin.PLUGIN_ID);
		Preferences connections = preferences.node(SAVED);
		for (Iterator i = connectionDetails.keySet().iterator(); i.hasNext();) {
			String target = (String) i.next();
			ConnectionDetails details = (ConnectionDetails) connectionDetails.get(target);
			Preferences p = connections.node(target);
			p.put(ConnectionDetails.CONTAINER_TYPE, details.getContainerType());
			p.put(ConnectionDetails.TARGET_URI, details.getTargetURI());
			p.put(ConnectionDetails.NICKNAME, details.getNickname());
			p.put(ConnectionDetails.PASSWORD, details.getPassword());
		}
		try {
			connections.flush();
		} catch (BackingStoreException e) {
			ClientPlugin.getDefault().getLog().log(new Status(IStatus.ERROR, ClientPlugin.PLUGIN_ID, BACKING_STORE_SAVE_ERROR, Messages.AccountStart_EXCEPTION_SAVING_CONNECTION_DETAILS, e));
		}
	}

	public void loadConnectionDetailsFromPreferenceStore() {
		try {
			Preferences preferences = InstanceScope.INSTANCE.getNode(ClientPlugin.PLUGIN_ID);
			Preferences connections = preferences.node(SAVED);
			String[] targets = connections.childrenNames();
			for (int i = 0; i < targets.length; i++) {
				String target = targets[i];
				Preferences node = connections.node(target);
				if (node != null) {
					addConnectionDetails(new ConnectionDetails(node.get(ConnectionDetails.CONTAINER_TYPE, ""), node.get( //$NON-NLS-1$
							ConnectionDetails.TARGET_URI, ""), //$NON-NLS-1$
							node.get(ConnectionDetails.NICKNAME, ""), //$NON-NLS-1$
							node.get(ConnectionDetails.PASSWORD, ""))); //$NON-NLS-1$
				}
			}
		} catch (BackingStoreException e) {
			ClientPlugin.getDefault().getLog().log(new Status(IStatus.ERROR, ClientPlugin.PLUGIN_ID, BACKING_STORE_LOAD_ERROR, Messages.AccountStart_EXCEPTION_LOADING_CONNECTION_DETAILS, e));
		}
	}
}
