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

public interface IRemoteFilter {

	/**
	 * Filter using a remote service's properties.
	 * <p>
	 * The filter is executed using the keys and values of the referenced
	 * service's properties. The keys are case insensitively matched with the
	 * filter.
	 * 
	 * @param reference
	 *            The reference to the service whose properties are used in the
	 *            match.
	 * 
	 * @return <code>true</code> if the service's properties match this
	 *         filter; <code>false</code> otherwise.
	 */
	public boolean match(IRemoteServiceReference reference);

	/**
	 * Filter using a <code>Dictionary</code> object. The Filter is executed
	 * using the <code>Dictionary</code> object's keys and values. The keys
	 * are case insensitively matched with the filter.
	 * 
	 * @param dictionary
	 *            The <code>Dictionary</code> object whose keys are used in
	 *            the match. Will be <code>null</code>.
	 * 
	 * @return <code>true</code> if the <code>Dictionary</code> object's
	 *         keys and values match this filter; <code>false</code>
	 *         otherwise.
	 * 
	 * @throws IllegalArgumentException
	 *             If <code>dictionary</code> contains case variants of the
	 *             same key name.
	 */
	public boolean match(Dictionary dictionary);

	/**
	 * Returns this <code>Filter</code> object's filter string.
	 * <p>
	 * The filter string is normalized by removing whitespace which does not
	 * affect the meaning of the filter.
	 * 
	 * @return Filter string.
	 */
	public String toString();

	/**
	 * Compares this <code>Filter</code> object to another object.
	 * 
	 * @param obj
	 *            The object to compare against this <code>Filter</code>
	 *            object.
	 * 
	 * @return If the other object is a <code>Filter</code> object, then
	 *         returns <code>this.toString().equals(obj.toString()</code>;<code>false</code>
	 *         otherwise.
	 */
	public boolean equals(Object obj);

	/**
	 * Returns the hashCode for this <code>Filter</code> object.
	 * 
	 * @return The hashCode of the filter string; that is,
	 *         <code>this.toString().hashCode()</code>.
	 */
	public int hashCode();

	/**
	 * Filter with case sensitivity using a <code>Dictionary</code> object.
	 * The Filter is executed using the <code>Dictionary</code> object's keys
	 * and values. The keys are case sensitively matched with the filter.
	 * 
	 * @param dictionary
	 *            The <code>Dictionary</code> object whose keys are used in
	 *            the match.
	 * 
	 * @return <code>true</code> if the <code>Dictionary</code> object's
	 *         keys and values match this filter; <code>false</code>
	 *         otherwise.
	 * 
	 * @since 1.3
	 */
	public boolean matchCase(Dictionary dictionary);

}
