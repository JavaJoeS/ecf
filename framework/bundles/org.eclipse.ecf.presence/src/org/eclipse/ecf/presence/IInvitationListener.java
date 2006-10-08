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
package org.eclipse.ecf.presence;

import org.eclipse.ecf.core.identity.ID;

public interface IInvitationListener {
	
	/**
	 * Handle notification of a received invitation to join room
	 * @param roomID the room id associated with the invitation
	 * @param from the id of the sender
	 * @param to the id of the intended receiver
	 * @param subject a subject for the invitation
	 * @param body a message body for the invitation
	 */
	public void handleInvitationReceived(ID roomID, ID from, ID to, String subject, String body);
}
