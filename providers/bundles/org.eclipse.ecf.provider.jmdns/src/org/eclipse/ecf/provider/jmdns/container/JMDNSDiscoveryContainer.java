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
package org.eclipse.ecf.provider.jmdns.container;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import javax.jmdns.ServiceTypeListener;

import org.eclipse.core.runtime.Platform;
import org.eclipse.ecf.core.ContainerConnectException;
import org.eclipse.ecf.core.IContainer;
import org.eclipse.ecf.core.IContainerListener;
import org.eclipse.ecf.core.events.ContainerConnectedEvent;
import org.eclipse.ecf.core.events.ContainerConnectingEvent;
import org.eclipse.ecf.core.events.ContainerDisconnectedEvent;
import org.eclipse.ecf.core.events.ContainerDisconnectingEvent;
import org.eclipse.ecf.core.events.ContainerDisposeEvent;
import org.eclipse.ecf.core.events.IContainerEvent;
import org.eclipse.ecf.core.identity.ID;
import org.eclipse.ecf.core.identity.IDCreateException;
import org.eclipse.ecf.core.identity.IDFactory;
import org.eclipse.ecf.core.identity.Namespace;
import org.eclipse.ecf.core.security.IConnectContext;
import org.eclipse.ecf.core.util.Trace;
import org.eclipse.ecf.discovery.IServiceInfo;
import org.eclipse.ecf.discovery.IServiceListener;
import org.eclipse.ecf.discovery.IServiceProperties;
import org.eclipse.ecf.discovery.IServiceTypeListener;
import org.eclipse.ecf.discovery.ServiceContainerEvent;
import org.eclipse.ecf.discovery.ServiceProperties;
import org.eclipse.ecf.discovery.identity.ServiceID;
import org.eclipse.ecf.discovery.service.IDiscoveryService;
import org.eclipse.ecf.internal.provider.jmdns.JMDNSDebugOptions;
import org.eclipse.ecf.internal.provider.jmdns.JMDNSPlugin;
import org.eclipse.ecf.internal.provider.jmdns.Messages;
import org.eclipse.ecf.provider.jmdns.identity.JMDNSServiceID;

public class JMDNSDiscoveryContainer implements IContainer,
		IDiscoveryService, ServiceListener, ServiceTypeListener {
	public static final int DEFAULT_REQUEST_TIMEOUT = 3000;
	protected static String JMDNS_NAMESPACE_ID = Messages
			.getString("JMDNSPlugin.namespace.identifier"); //$NON-NLS-1$;

	ContainerConfig config = null;
	InetAddress intf = null;
	JmDNS jmdns = null;
	int requestTimeout = DEFAULT_REQUEST_TIMEOUT;
	Map serviceListeners = new HashMap();
	Vector serviceTypeListeners = new Vector();
	private Vector listeners = new Vector();

	public JMDNSDiscoveryContainer() throws IOException, IDCreateException {
		this(null);
	}

	public ID getID() {
		if (config == null)
			return null;
		else
			return config.getID();
	}

	public JMDNSDiscoveryContainer(InetAddress addr) throws IOException,
			IDCreateException {
		super();
		intf = (addr == null) ? InetAddress.getLocalHost() : addr;
		this.config = new ContainerConfig(IDFactory.getDefault()
				.createStringID(JMDNSDiscoveryContainer.class.getName()));
	}

	public void addServiceListener(ServiceID type, IServiceListener listener) {
		if (type == null || listener == null)
			return;
		synchronized (serviceListeners) {
			Vector v = (Vector) serviceListeners.get(type);
			if (v == null) {
				v = new Vector();
				serviceListeners.put(type, v);
			}
			v.add(listener);
		}
	}

	public void addServiceTypeListener(IServiceTypeListener listener) {
		serviceTypeListeners.add(listener);
	}

	protected void fireContainerEvent(IContainerEvent event) {
		synchronized (listeners) {
			for (Iterator i = listeners.iterator(); i.hasNext();) {
				IContainerListener l = (IContainerListener) i.next();
				l.handleEvent(event);
			}
		}
	}

	public void dispose() {
		disconnect();
		fireContainerEvent(new ContainerDisposeEvent(getID()));
	}

	protected void fireServiceAdded(ServiceEvent arg0) {
		IServiceInfo iinfo = createIServiceInfoFromServiceEvent(arg0);
		ServiceID svcID = createServiceID(arg0.getType(), null);
		synchronized (serviceListeners) {
			Vector v = (Vector) serviceListeners.get(svcID);
			if (v != null) {
				for (Iterator i = v.iterator(); i.hasNext();) {
					IServiceListener l = (IServiceListener) i.next();
					l.serviceAdded(new ServiceContainerEvent(iinfo, config
							.getID()));
				}
			}
		}
	}

	protected void fireServiceRemoved(ServiceEvent arg0) {
		IServiceInfo iinfo = createIServiceInfoFromServiceEvent(arg0);
		ServiceID svcID = createServiceID(arg0.getType(), null);
		synchronized (serviceListeners) {
			Vector v = (Vector) serviceListeners.get(svcID);
			if (v != null) {
				for (Iterator i = v.iterator(); i.hasNext();) {
					IServiceListener l = (IServiceListener) i.next();
					l.serviceRemoved(new ServiceContainerEvent(iinfo, config
							.getID()));
				}
			}
		}
	}

	protected void fireServiceResolved(ServiceEvent arg0) {
		IServiceInfo iinfo = createIServiceInfoFromServiceEvent(arg0);
		ServiceID svcID = createServiceID(arg0.getType(), null);
		synchronized (serviceListeners) {
			Vector v = (Vector) serviceListeners.get(svcID);
			if (v != null) {
				for (Iterator i = v.iterator(); i.hasNext();) {
					IServiceListener l = (IServiceListener) i.next();
					l.serviceResolved(new ServiceContainerEvent(iinfo, config
							.getID()));
				}
			}
		}
	}

	protected void fireServiceTypeAdded(ServiceEvent arg0) {
		synchronized (serviceTypeListeners) {
			for (Iterator i = serviceTypeListeners.iterator(); i.hasNext();) {
				IServiceTypeListener l = (IServiceTypeListener) i.next();
				l.serviceTypeAdded(new ServiceContainerEvent(
						createIServiceInfoFromServiceEvent(arg0), config
								.getID()));
			}
		}
	}

	public Object getAdapter(Class adapter) {
		if (adapter.isInstance(this)) {
			return this;
		} else {
			return Platform.getAdapterManager().getAdapter(this, adapter);
		}
	}

	public ID getConnectedID() {
		return null;
	}

	public IServiceInfo getServiceInfo(ServiceID service, int timeout) {
		Trace.entering(JMDNSPlugin.getDefault(),
				JMDNSDebugOptions.METHODS_ENTERING, this.getClass(),
				"getServiceInfo",
				new Object[] { service, new Integer(timeout) });
		IServiceInfo result = null;
		if (jmdns != null)
			result = createIServiceInfoFromServiceInfo(jmdns
					.getServiceInfo(service.getServiceType(), service
							.getServiceName(), timeout));
		Trace.exiting(JMDNSPlugin.getDefault(),
				JMDNSDebugOptions.METHODS_ENTERING, this.getClass(),
				"getServiceInfo", result);
		return result;
	}

	public IServiceInfo[] getServices(ServiceID type) {
		IServiceInfo svs[] = new IServiceInfo[0];
		if (jmdns != null) {
			ServiceInfo[] svcs = jmdns.list(type.getServiceType());
			if (svcs != null) {
				svs = new IServiceInfo[svcs.length];
				for (int i = 0; i < svcs.length; i++) {
					svs[i] = createIServiceInfoFromServiceInfo(svcs[i]);
				}
			}
		}
		return svs;
	}

	public void connect(ID groupID, IConnectContext joinContext)
			throws ContainerConnectException {
		if (this.jmdns != null)
			throw new ContainerConnectException("Already connected");
		fireContainerEvent(new ContainerConnectingEvent(this.getID(), groupID,
				joinContext));
		try {
			if (Platform.inDebugMode()) {
				Logger logger = Logger.getLogger(JmDNS.class.toString());
				ConsoleHandler handler = new ConsoleHandler();
				logger.addHandler(handler);
				logger.setLevel(Level.FINER);
				handler.setLevel(Level.FINER);
			}
			this.jmdns = new JmDNS(intf);
			jmdns.addServiceTypeListener(this);
			if (groupID != null && groupID instanceof JMDNSServiceID) {
				ServiceID svcid = (ServiceID) groupID;
				jmdns.addServiceListener(svcid.getServiceType(), this);
			}
		} catch (IOException e) {
			ContainerConnectException soe = new ContainerConnectException(
					"Exception creating JmDNS instance");
			soe.setStackTrace(e.getStackTrace());
			throw soe;
		}
		fireContainerEvent(new ContainerConnectedEvent(this.getID(), groupID));
	}

	public void disconnect() {
		fireContainerEvent(new ContainerDisconnectingEvent(this.getID(),
				getConnectedID()));
		if (this.jmdns != null) {
			jmdns.close();
			jmdns = null;
		}
		fireContainerEvent(new ContainerDisconnectedEvent(this.getID(),
				getConnectedID()));
	}

	protected IServiceInfo createIServiceInfoFromServiceEvent(ServiceEvent event) {
		ServiceID sID = createServiceID(event.getType(), event.getName());
		ServiceInfo sinfo = event.getInfo();
		if (sinfo != null) {
			return createIServiceInfoFromServiceInfo(sinfo);
		}
		IServiceInfo newInfo = new JMDNSServiceInfo(null, sID, -1, -1, -1,
				new ServiceProperties());
		return newInfo;
	}

	protected IServiceInfo createIServiceInfoFromServiceInfo(
			final ServiceInfo serviceInfo) {
		if (serviceInfo == null)
			return null;
		ServiceID sID = createServiceID(serviceInfo.getType(), serviceInfo
				.getName());
		InetAddress addr = serviceInfo.getAddress();
		int port = serviceInfo.getPort();
		int priority = serviceInfo.getPriority();
		int weight = serviceInfo.getWeight();
		Properties props = new Properties();
		for (Enumeration e = serviceInfo.getPropertyNames(); e
				.hasMoreElements();) {
			String name = (String) e.nextElement();
			Object value = serviceInfo.getPropertyString(name);
			if (value == null)
				value = serviceInfo.getPropertyBytes(name);
			if (value != null)
				props.put(name, value);
		}
		final ServiceProperties svcProperties = new ServiceProperties(props);
		IServiceProperties newProps = new IServiceProperties() {
			public Enumeration getPropertyNames() {
				return svcProperties.getPropertyNames();
			}

			public String getPropertyString(String name) {
				return svcProperties.getPropertyString(name);
			}

			public byte[] getPropertyBytes(String name) {
				return svcProperties.getPropertyBytes(name);
			}

			public Object getProperty(String name) {
				return svcProperties.getPropertyBytes(name);
			}

			public Object setProperty(String name, Object value) {
				return svcProperties.setProperty(name, value);
			}

			public Object setPropertyBytes(String name, byte[] value) {
				return svcProperties.setPropertyBytes(name, value);
			}

			public Object setPropertyString(String name, String value) {
				return svcProperties.setPropertyString(name, value);
			}
		};
		IServiceInfo newInfo = new JMDNSServiceInfo(addr, sID, port, priority,
				weight, newProps);
		return newInfo;
	}

	protected ServiceID createServiceID(String type, String name) {
		ServiceID id = null;
		try {
			id = (ServiceID) IDFactory.getDefault().createID(
					JMDNS_NAMESPACE_ID, new Object[] { type, name });
		} catch (IDCreateException e) {
			// Should never happen
			Trace.catching(JMDNSPlugin.getDefault(),
					JMDNSDebugOptions.EXCEPTIONS_CATCHING, this.getClass(),
					"createServiceID", e);
		}
		return id;
	}

	protected ServiceInfo createServiceInfoFromIServiceInfo(
			IServiceInfo serviceInfo) {
		if (serviceInfo == null)
			return null;
		ServiceID sID = serviceInfo.getServiceID();
		Hashtable props = new Hashtable();
		IServiceProperties svcProps = serviceInfo.getServiceProperties();
		if (svcProps != null) {
			for (Enumeration e = svcProps.getPropertyNames(); e
					.hasMoreElements();) {
				String key = (String) e.nextElement();
				Object val = svcProps.getProperty(key);
				if (val != null) {
					props.put(key, val);
				}
			}
		}
		ServiceInfo si = new ServiceInfo(sID.getServiceType(), sID
				.getServiceName(), serviceInfo.getPort(), serviceInfo
				.getPriority(), serviceInfo.getWeight(), props);
		return si;
	}

	protected String prepareSvcTypeForBonjour(String svcType) {
		String result = svcType;
		if (svcType.endsWith(".local.")) {
			result = svcType.substring(0, svcType.indexOf(".local."));
		}
		return result;
	}

	public void registerService(IServiceInfo serviceInfo) throws IOException {
		registerServiceWithJmDNS(serviceInfo);
	}

	public void registerServiceType(ServiceID serviceType) {
		String type = serviceType.getServiceType();
		registerServiceType(type);
	}

	public void registerServiceType(String serviceType) {
		if (jmdns != null) {
			jmdns.registerServiceType(serviceType);
			jmdns.addServiceListener(serviceType, this);
		}
	}

	protected void registerServiceWithJmDNS(IServiceInfo serviceInfo)
			throws IOException {
		if (jmdns != null) {
			jmdns
					.registerService(createServiceInfoFromIServiceInfo(serviceInfo));
		}
	}

	public void removeServiceListener(ServiceID type, IServiceListener listener) {
		if (type == null || listener == null)
			return;
		synchronized (serviceListeners) {
			Vector v = (Vector) serviceListeners.get(type);
			if (v == null) {
				return;
			}
			v.remove(listener);
		}
	}

	public void removeServiceTypeListener(IServiceTypeListener listener) {
		serviceTypeListeners.add(listener);
	}

	public void requestServiceInfo(ServiceID service, int timeout) {
		if (jmdns != null) {
			jmdns.requestServiceInfo(service.getServiceType(), service
					.getServiceName(), timeout);
		}
	}

	public void serviceAdded(ServiceEvent arg0) {
		if (jmdns != null) {
			try {
				fireServiceAdded(arg0);
			} catch (Exception e) {
				Trace.catching(JMDNSPlugin.getDefault(),
						JMDNSDebugOptions.EXCEPTIONS_CATCHING, this.getClass(),
						"serviceAdded", e);
			}
		}
	}

	public void serviceRemoved(ServiceEvent arg0) {
		if (jmdns != null) {
			try {
				fireServiceRemoved(arg0);
			} catch (Exception e) {
				Trace.catching(JMDNSPlugin.getDefault(),
						JMDNSDebugOptions.EXCEPTIONS_CATCHING, this.getClass(),
						"serviceRemoved", e);
			}
		}
	}

	public void serviceResolved(ServiceEvent arg0) {
		if (jmdns != null) {
			try {
				fireServiceResolved(arg0);
			} catch (Exception e) {
				Trace.catching(JMDNSPlugin.getDefault(),
						JMDNSDebugOptions.EXCEPTIONS_CATCHING, this.getClass(),
						"serviceResolved", e);
			}
		}
	}

	public void serviceTypeAdded(ServiceEvent arg0) {
		if (jmdns != null) {
			try {
				fireServiceTypeAdded(arg0);
			} catch (Exception e) {
				Trace.catching(JMDNSPlugin.getDefault(),
						JMDNSDebugOptions.EXCEPTIONS_CATCHING, this.getClass(),
						"serviceResolved", e);
			}
		}
	}

	public void unregisterService(IServiceInfo serviceInfo) {
		if (jmdns != null) {
			jmdns
					.unregisterService(createServiceInfoFromIServiceInfo(serviceInfo));
		}
	}

	public Namespace getConnectNamespace() {
		return IDFactory.getDefault().getNamespaceByName(JMDNS_NAMESPACE_ID);
	}

	public void addListener(IContainerListener l) {
		synchronized (listeners) {
			listeners.add(l);
		}
	}

	public void removeListener(IContainerListener l) {
		synchronized (listeners) {
			listeners.remove(l);
		}
	}
}
