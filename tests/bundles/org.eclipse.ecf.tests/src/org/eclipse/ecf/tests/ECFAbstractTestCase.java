/****************************************************************************
 * Copyright (c) 2006, 2007 Composent, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Composent, Inc. - initial API and implementation
 *****************************************************************************/
package org.eclipse.ecf.tests;

import junit.framework.TestCase;

import org.eclipse.ecf.core.util.Trace;
import org.eclipse.ecf.internal.tests.Activator;

/**
 * Base ECF test case provide utility methods for subclasses.
 */
public abstract class ECFAbstractTestCase extends TestCase {

	/**
	 * Sleep the current thread for given amount of time (in ms).  Optionally print messages before starting
	 * sleeping and after completing sleeping.
	 * @param sleepTime time in milliseconds to sleep
	 * @param startMessage
	 * @param endMessage
	 */
	protected void sleep(long sleepTime, String startMessage, String endMessage) {
		if (startMessage != null) Trace.trace(Activator.PLUGIN_ID, startMessage);
		try {
			Thread.sleep(sleepTime);
		} catch (InterruptedException e) {
		}
		if (endMessage != null) Trace.trace(Activator.PLUGIN_ID, endMessage);
	}
	
	/**
	 * Sleep the current thread for given amount of time (in ms).
	 * @param sleepTime time in milliseconds to sleep
	 */
	protected void sleep(long sleepTime) {
		sleep(sleepTime, null, null);
	}
}
