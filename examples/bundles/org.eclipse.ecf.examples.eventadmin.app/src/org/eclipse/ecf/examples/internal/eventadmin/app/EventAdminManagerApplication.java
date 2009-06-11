/*******************************************************************************
 * Copyright (c) 2009 EclipseSource and others. All rights reserved. This
 * program and the accompanying materials are made available under the terms of
 * the Eclipse Public License v1.0 which accompanies this distribution, and is
 * available at http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   EclipseSource - initial API and implementation
 ******************************************************************************/
package org.eclipse.ecf.examples.internal.eventadmin.app;

import java.util.Map;

import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.event.EventHandler;

public class EventAdminManagerApplication extends AbstractEventAdminApplication
		implements IApplication {

	private static final String DEFAULT_CONTAINER_TYPE = "ecf.jms.activemq.tcp.manager";
	public static final String DEFAULT_CONTAINER_ID = "tcp://localhost:61616/exampleTopic";
	public static final String DEFAULT_TOPIC = "defaultTopic";

	private TestSender testSender;
	private ServiceRegistration testEventHandlerRegistration;

	public Object start(IApplicationContext context) throws Exception {
		// Do setup in abstract super class
		super.start(context);
		
		// XXX for testing, setup an event handler
		testEventHandlerRegistration = bundleContext.registerService(
				EventHandler.class.getName(), new TestEventHandler(), null);
		
		// XXX for testing, setup a test sender
		testSender = new TestSender(eventAdminImpl, topic, container.getID().getName());
		new Thread(testSender).start();
		
		// Now just wait until we're stopped
		waitForDone();
		
		return new Integer(0);
	}

	public void stop() {
		if (testSender != null) {
			testSender.stop();
			testSender = null;
		}
		if (testEventHandlerRegistration != null) {
			testEventHandlerRegistration.unregister();
			testEventHandlerRegistration = null;
		}
		super.stop();
	}

	protected void processArgs(Map args) {
		containerType = DEFAULT_CONTAINER_TYPE;
		containerId = DEFAULT_CONTAINER_ID;
		targetId = null;
		topic = DEFAULT_TOPIC;
	}

}
