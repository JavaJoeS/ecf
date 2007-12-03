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

import java.util.Dictionary;
import org.eclipse.core.runtime.IAdaptable;
import org.eclipse.ecf.core.identity.ID;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;

/**
 * Entry point remote service container adapter. This is the entry point
 * innterface for accessing remote services through ECF containers.
 * 
 */
public interface IRemoteServiceContainerAdapter extends IAdaptable {

	/**
	 * Add listener for remote service registration/unregistration for this
	 * container
	 * 
	 * @param listener
	 *            notified of service registration/unregistration events. Must
	 *            not be <code>null</code> .
	 */
	public void addRemoteServiceListener(IRemoteServiceListener listener);

	/**
	 * Remove remote service registration/unregistration listener for this
	 * container.
	 * 
	 * @param listener
	 *            to remove. Must not be <code>null</code> .
	 */
	public void removeRemoteServiceListener(IRemoteServiceListener listener);

	/**
	 * Register a new remote service. This method is to be called by the service
	 * server...i.e. the client that wishes to make available a service to other
	 * client within this container.
	 * 
	 * @param clazzes
	 *            the interface classes that the service exposes to remote
	 *            clients. Must not be <code>null</code> and must not be an
	 *            empty array.
	 * @param service
	 *            the service object itself. This object must implement all of
	 *            the classes specified by the first parameter
	 * @param properties
	 *            to be associated with service
	 * @return IRemoteServiceRegistration the service registration. Will not
	 *         return <code>null</code> .
	 */
	public IRemoteServiceRegistration registerRemoteService(String[] clazzes, Object service, Dictionary properties);

	/**
	 * Returns an array of <code>IRemoteServiceReference</code> objects. The
	 * returned array of <code>IRemoteServiceReference</code> objects contains
	 * services that were registered under the specified class and match the
	 * specified idFilter, and filter criteria.
	 * 
	 * <p>
	 * The list is valid at the time of the call to this method, however since
	 * the Framework is a very dynamic environment, services can be modified or
	 * unregistered at anytime.
	 * 
	 * <p>
	 * <code>idFilter</code> is used to select a registered services that were
	 * registered by a given set of containers with id in idFilter. Only
	 * services exposed by a container with id in idFilter will be returned.
	 * 
	 * <p>
	 * If <code>idFilter</code> is <code>null</code>, all containers are
	 * considered to match the filter.
	 * 
	 * <p>
	 * <code>filter</code> is used to select the registered service whose
	 * properties objects contain keys and values which satisfy the filter. See
	 * {@link Filter} for a description of the filter string syntax.
	 * 
	 * <p>
	 * If <code>filter</code> is <code>null</code>, all registered services
	 * are considered to match the filter. If <code>filter</code> cannot be
	 * parsed, an {@link InvalidSyntaxException} will be thrown with a human
	 * readable message where the filter became unparsable.
	 * 
	 * @param idFilter
	 *            an array of ID instances that will restrict the search for
	 *            matching container ids If null, all remote containers will be
	 *            considered in search for matching IRemoteServiceReference
	 *            instances. May be <code>null</code> .
	 * 
	 * @param clazz
	 *            the fully qualified name of the interface class that describes
	 *            the desired service. Must not be <code>null</code> .
	 * @param filter
	 *            The filter criteria. May be <code>null</code> .
	 * @return IRemoteServiceReference [] the matching IRemoteServiceReferences
	 * 
	 * @throws InvalidSyntaxException If filter contains an invalid filter string that cannot be parsed.
	 */
	public IRemoteServiceReference[] getRemoteServiceReferences(ID[] idFilter, String clazz, String filter) throws InvalidSyntaxException;

	/**
	 * Get remote service for given IRemoteServiceReference. Note that clients
	 * that call this method successfully should later call
	 * {@link IRemoteServiceContainerAdapter#ungetRemoteService(IRemoteServiceReference)}
	 * when the IRemoteService will no longer be used.
	 * 
	 * @param reference
	 *            the IRemoteServiceReference for the desired service. Must not
	 *            be <code>null</code> .
	 * @return IRemoteService representing the remote service. If remote service
	 *         no longer exists for reference, then <code>null</code> is
	 *         returned.
	 * 
	 * @see #ungetRemoteService(IRemoteServiceReference)
	 */
	public IRemoteService getRemoteService(IRemoteServiceReference reference);

	/**
	 * Unget IRemoteServiceReference. Release all resources associated with the
	 * given IRemoteServiceReference. This method should be called by users of
	 * the IRemoteServiceReference that have previously called
	 * {@link IRemoteServiceContainerAdapter#getRemoteService(IRemoteServiceReference)}.
	 * If this method returns true, then the previously used IRemoteService will
	 * no longer be usable.
	 * 
	 * @param reference
	 *            the IRemoteServiceReference to unget
	 * @return true if unget successful, false if not. If this method returns
	 *         true, then the IRemoteService instance previously retrieved via
	 *         the given IRemoteServiceReference instance provided will no
	 *         longer be usable.
	 * 
	 * @see #getRemoteService(IRemoteServiceReference)
	 */
	public boolean ungetRemoteService(IRemoteServiceReference reference);

}
