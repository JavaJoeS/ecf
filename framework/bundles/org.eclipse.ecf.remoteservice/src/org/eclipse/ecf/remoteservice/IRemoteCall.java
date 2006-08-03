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

package org.eclipse.ecf.remoteservice;

/**
 * Instances of this interface are used to make a 
 * a remote call via one of the methods on IRemoteService
 * 
 * @see IRemoteService
 */
public interface IRemoteCall {
	/**
	 * Get the method name to call on the remote.  Must return a non-null and non-empty
	 * string
	 * @return String name of method to call on the remote
	 */
	public String getMethod();
	/**
	 * Get the method parameters of the method to call on the remote.  Must return a non-null 
	 * and non-empty array of Object parameters.  The given Objects in the array must be
	 * be Serializable so that they may be serialized to deliver to remote.
	 * 
	 * @return Object [] the parameters to be provided for this call
	 */
	public Object [] getParameters();
	/**
	 * Get timeout (in ms) for the remote call.  
	 * 
	 * @return long timeout in ms
	 */
	public long getTimeout();
}
