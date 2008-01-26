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

package org.eclipse.ecf.discovery.service;

import org.eclipse.ecf.discovery.IDiscoveryContainerAdapter;

/**
 * OSGI discovery service interface.  This interface should be registered
 * by providers when they wish to expose discovery services to OSGI
 * service clients.
 */
public interface IDiscoveryService extends IDiscoveryContainerAdapter {
	// All methods provided by superclass
	public static final String CONTAINER_ID = "org.eclipse.ecf.discovery.containerID"; //$NON-NLS-1$
}
