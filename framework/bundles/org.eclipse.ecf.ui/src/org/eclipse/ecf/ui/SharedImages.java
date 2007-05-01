/*******************************************************************************
 * Copyright (c) 2007 Remy Suen, Composent, Inc., and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Remy Suen <remy.suen@gmail.com> - initial API and implementation
 ******************************************************************************/
package org.eclipse.ecf.ui;

import org.eclipse.ecf.internal.ui.Activator;
import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.swt.graphics.Image;

/**
 * Shared images for ECF user interface elements.
 */
public final class SharedImages {

	public static final String IMG_USER_AVAILABLE = "IMG_USER_AVAILABLE"; //$NON-NLS-1$

	public static final String IMG_USER_UNAVAILABLE = "IMG_USER_UNAVAILABLE"; //$NON-NLS-1$

	public static final String IMG_USER_DND = "IMG_USER_DND"; //$NON-NLS-1$

	public static final String IMG_USER_AWAY = "IMG_USER_AWAY"; //$NON-NLS-1$

	public static final String IMG_GROUP = "IMG_GROUP"; //$NON-NLS-1$

	public static final String IMG_SEND = "IMG_SEND"; //$NON-NLS-1$

	public static final String IMG_DISCONNECT_DISABLED = "IMG_DISCONNECT_DISABLED"; //$NON-NLS-1$

	public static final String IMG_DISCONNECT = "IMG_DISCONNECT"; //$NON-NLS-1$

	public static final String IMG_ADD_GROUP = "IMG_ADD_GROUP"; //$NON-NLS-1$

	public static final String IMG_ADD_BUDDY = "IMG_ADD_BUDDY"; //$NON-NLS-1$

	public static final String IMG_ADD_CHAT = "IMG_ADD_CHAT"; //$NON-NLS-1$

	public static final String IMG_MESSAGE = "IMG_MESSAGE"; //$NON-NLS-1$

	public static final String IMG_ADD = "IMG_ADD"; //$NON-NLS-1$

	public static ImageDescriptor getImageDescriptor(String key) {
		return Activator.getDefault().getImageRegistry().getDescriptor(key);
	}

	public static Image getImage(String key) {
		return Activator.getDefault().getImageRegistry().get(key);
	}

	private SharedImages() {
		// private constructor to prevent instantiation
	}

}
