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
package org.eclipse.ecf.internal.provider.filetransfer;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;
import org.eclipse.core.net.proxy.IProxyService;
import org.eclipse.core.runtime.*;
import org.eclipse.ecf.core.util.LogHelper;
import org.eclipse.ecf.core.util.PlatformHelper;
import org.eclipse.ecf.filetransfer.service.*;
import org.eclipse.ecf.provider.filetransfer.retrieve.MultiProtocolRetrieveAdapter;
import org.eclipse.osgi.util.NLS;
import org.osgi.framework.*;
import org.osgi.service.log.LogService;
import org.osgi.service.url.*;
import org.osgi.util.tracker.ServiceTracker;

/**
 * The activator class controls the plug-in life cycle
 */
public class Activator implements BundleActivator {

	private static final String CLASS_ATTR = "class"; //$NON-NLS-1$
	private static final String PRIORITY_ATTR = "priority"; //$NON-NLS-1$
	private static final int DEFAULT_PRIORITY = 100;
	private static final String PROTOCOL_ATTR = "protocol"; //$NON-NLS-1$
	private static final String[] jvmSchemes = new String[] {Messages.FileTransferNamespace_Http_Protocol, Messages.FileTransferNamespace_Ftp_Protocol, Messages.FileTransferNamespace_File_Protocol, Messages.FileTransferNamespace_Jar_Protocol, Messages.FileTransferNamespace_Https_Protocol, Messages.FileTransferNamespace_Mailto_Protocol, Messages.FileTransferNamespace_Gopher_Protocol};

	private static final String URL_HANDLER_PROTOCOL_NAME = "url.handler.protocol"; //$NON-NLS-1$

	private static final String URLSTREAM_HANDLER_SERVICE_NAME = "org.osgi.service.url.URLStreamHandlerService"; //$NON-NLS-1$

	// The plug-in ID
	public static final String PLUGIN_ID = "org.eclipse.ecf.provider.filetransfer"; //$NON-NLS-1$

	private static final String RETRIEVE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME = "retrieveFileTransferProtocolFactory"; //$NON-NLS-1$

	private static final String RETRIEVE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT = PLUGIN_ID + "." //$NON-NLS-1$
			+ RETRIEVE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME;

	private static final String SEND_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME = "sendFileTransferProtocolFactory"; //$NON-NLS-1$

	private static final String SEND_FILETRANSFER_PROTOCOL_FACTORY_EPOINT = PLUGIN_ID + "." //$NON-NLS-1$
			+ SEND_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME;

	private static final String BROWSE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME = "browseFileTransferProtocolFactory"; //$NON-NLS-1$

	private static final String BROWSE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT = PLUGIN_ID + "." //$NON-NLS-1$
			+ BROWSE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME;

	// The shared instance
	private static Activator plugin;

	private BundleContext context = null;

	private ServiceRegistration fileTransferServiceRegistration;

	private ServiceTracker logServiceTracker = null;
	private ServiceTracker extensionRegistryTracker = null;

	private Map retrieveFileTransferProtocolMap = null;

	private Map sendFileTransferProtocolMap = null;

	private Map browseFileTransferProtocolMap = null;

	private ServiceTracker adapterManagerTracker = null;

	private ServiceTracker proxyServiceTracker = null;

	private IRegistryChangeListener registryChangeListener = new IRegistryChangeListener() {

		public void registryChanged(IRegistryChangeEvent event) {
			final IExtensionDelta retrieveDelta[] = event.getExtensionDeltas(PLUGIN_ID, RETRIEVE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME);
			for (int i = 0; i < retrieveDelta.length; i++) {
				switch (retrieveDelta[i].getKind()) {
					case IExtensionDelta.ADDED :
						addRetrieveExtensions(retrieveDelta[i].getExtension().getConfigurationElements());
						break;
					case IExtensionDelta.REMOVED :
						removeRetrieveExtensions(retrieveDelta[i].getExtension().getConfigurationElements());
						break;
				}
			}
			final IExtensionDelta sendDelta[] = event.getExtensionDeltas(PLUGIN_ID, SEND_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME);
			for (int i = 0; i < sendDelta.length; i++) {
				switch (sendDelta[i].getKind()) {
					case IExtensionDelta.ADDED :
						addSendExtensions(sendDelta[i].getExtension().getConfigurationElements());
						break;
					case IExtensionDelta.REMOVED :
						removeSendExtensions(sendDelta[i].getExtension().getConfigurationElements());
						break;
				}
			}
			final IExtensionDelta browseDelta[] = event.getExtensionDeltas(PLUGIN_ID, BROWSE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT_NAME);
			for (int i = 0; i < browseDelta.length; i++) {
				switch (browseDelta[i].getKind()) {
					case IExtensionDelta.ADDED :
						addBrowseExtensions(browseDelta[i].getExtension().getConfigurationElements());
						break;
					case IExtensionDelta.REMOVED :
						removeBrowseExtensions(browseDelta[i].getExtension().getConfigurationElements());
						break;
				}
			}
		}

	};

	/**
	 * The constructor
	 */
	public Activator() {
		//
	}

	protected LogService getLogService() {
		if (logServiceTracker == null) {
			logServiceTracker = new ServiceTracker(this.context, LogService.class.getName(), null);
			logServiceTracker.open();
		}
		return (LogService) logServiceTracker.getService();
	}

	public IProxyService getProxyService() {
		try {
			if (proxyServiceTracker == null) {
				proxyServiceTracker = new ServiceTracker(this.context, IProxyService.class.getName(), null);
				proxyServiceTracker.open();
			}
			return (IProxyService) proxyServiceTracker.getService();
		} catch (Exception e) {
			logNoProxyWarning(e);
		} catch (NoClassDefFoundError e) {
			logNoProxyWarning(e);
		}
		return null;
	}

	public static void logNoProxyWarning(Throwable e) {
		getDefault().log(new Status(IStatus.WARNING, Activator.PLUGIN_ID, IStatus.ERROR, "Warning: Platform proxy API not available", e)); //$NON-NLS-1$
	}

	public void log(IStatus status) {
		final LogService logService = getLogService();
		if (logService != null) {
			logService.log(LogHelper.getLogCode(status), LogHelper.getLogMessage(status), status.getException());
		}
	}

	public Bundle getBundle() {
		if (context == null)
			return null;
		return context.getBundle();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.eclipse.core.runtime.Plugins#start(org.osgi.framework.BundleContext)
	 */
	public void start(BundleContext ctxt) throws Exception {
		plugin = this;
		this.context = ctxt;
		fileTransferServiceRegistration = ctxt.registerService(IRetrieveFileTransferFactory.class.getName(), new IRetrieveFileTransferFactory() {
			public IRetrieveFileTransfer newInstance() {
				return new MultiProtocolRetrieveAdapter();
			}
		}, null);
		this.extensionRegistryTracker = new ServiceTracker(ctxt, IExtensionRegistry.class.getName(), null);
		this.extensionRegistryTracker.open();
		final IExtensionRegistry registry = getExtensionRegistry();
		if (registry != null) {
			registry.addRegistryChangeListener(registryChangeListener);
		}
		// Can't be lazy about this, as schemes need to be registered with
		// platform
		loadProtocolHandlers();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.eclipse.core.runtime.Plugin#stop(org.osgi.framework.BundleContext)
	 */
	public void stop(BundleContext ctxt) throws Exception {
		plugin = null;
		this.context = null;
		final IExtensionRegistry registry = getExtensionRegistry();
		if (registry != null) {
			registry.removeRegistryChangeListener(registryChangeListener);
		}
		if (extensionRegistryTracker != null) {
			extensionRegistryTracker.close();
			extensionRegistryTracker = null;
		}
		if (fileTransferServiceRegistration != null) {
			fileTransferServiceRegistration.unregister();
			fileTransferServiceRegistration = null;
		}
		if (adapterManagerTracker != null) {
			adapterManagerTracker.close();
			adapterManagerTracker = null;
		}
		if (proxyServiceTracker != null) {
			proxyServiceTracker.close();
			proxyServiceTracker = null;
		}
		this.context = null;
		if (this.retrieveFileTransferProtocolMap != null) {
			this.retrieveFileTransferProtocolMap.clear();
			this.retrieveFileTransferProtocolMap = null;
		}
		if (this.sendFileTransferProtocolMap != null) {
			this.sendFileTransferProtocolMap.clear();
			this.sendFileTransferProtocolMap = null;
		}
		if (this.browseFileTransferProtocolMap != null) {
			this.browseFileTransferProtocolMap.clear();
			this.browseFileTransferProtocolMap = null;
		}
	}

	/**
	 * Returns the shared instance
	 * 
	 * @return the shared instance
	 */
	public synchronized static Activator getDefault() {
		if (plugin == null) {
			plugin = new Activator();
		}
		return plugin;
	}

	public String[] getPlatformSupportedSchemes() {
		final ServiceTracker handlers = new ServiceTracker(context, URLSTREAM_HANDLER_SERVICE_NAME, null);
		handlers.open();
		final ServiceReference[] refs = handlers.getServiceReferences();
		final Set protocols = new HashSet();
		if (refs != null)
			for (int i = 0; i < refs.length; i++) {
				final Object protocol = refs[i].getProperty(URL_HANDLER_PROTOCOL_NAME);
				if (protocol instanceof String)
					protocols.add(protocol);
				else if (protocol instanceof String[]) {
					final String[] ps = (String[]) protocol;
					for (int j = 0; j < ps.length; j++)
						protocols.add(ps[j]);
				}
			}
		handlers.close();
		for (int i = 0; i < jvmSchemes.length; i++)
			protocols.add(jvmSchemes[i]);
		return (String[]) protocols.toArray(new String[] {});
	}

	public IExtensionRegistry getExtensionRegistry() {
		if (extensionRegistryTracker == null) {
			this.extensionRegistryTracker = new ServiceTracker(context, IExtensionRegistry.class.getName(), null);
			this.extensionRegistryTracker.open();
		}
		return (IExtensionRegistry) extensionRegistryTracker.getService();
	}

	static class ProtocolFactory implements Comparable {
		Object factory;
		int priority = 0;
		String id;

		public ProtocolFactory(Object factory, int priority, String id) {
			this.factory = factory;
			this.priority = priority;
			this.id = id;
		}

		public Object getFactory() {
			return factory;
		}

		public String getID() {
			return id;
		}

		/* (non-Javadoc)
		 * @see java.lang.Comparable#compareTo(java.lang.Object)
		 */
		public int compareTo(Object another) {
			if (!(another instanceof ProtocolFactory))
				return -1;
			ProtocolFactory other = (ProtocolFactory) another;
			if (this.priority == other.priority)
				return 0;
			return (this.priority < other.priority) ? -1 : 1;
		}
	}

	private int getPriority(IConfigurationElement configElement, String warning, String protocol) {
		// Get priority for new entry, if optional priority attribute specified
		final String priorityString = configElement.getAttribute(PRIORITY_ATTR);
		int priority = DEFAULT_PRIORITY;
		if (priorityString != null) {
			try {
				priority = new Integer(priorityString).intValue();
				// Make sure that any negative values are reset to 0 (highest priority)
				priority = (priority < 0) ? 0 : priority;
			} catch (NumberFormatException e) {
				// Give warning
				Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_PRIORITY_ERROR, new Object[] {warning, protocol, configElement.getDeclaringExtension().getContributor().getName(), priorityString, String.valueOf(DEFAULT_PRIORITY)}), null));
			}
		}
		return priority;
	}

	void addRetrieveExtensions(IConfigurationElement[] configElements) {
		String[] existingSchemes = getPlatformSupportedSchemes();
		for (int i = 0; i < configElements.length; i++) {
			final String protocol = configElements[i].getAttribute(PROTOCOL_ATTR);
			if (protocol == null || "".equals(protocol)) //$NON-NLS-1$
				return;
			String CONTRIBUTION_WARNING = Messages.Activator_WARNING_RETRIEVE_CONTRIBUTION_PREFIX;
			try {
				// First create factory clazz 
				final IRetrieveFileTransferFactory clazz = (IRetrieveFileTransferFactory) configElements[i].createExecutableExtension(CLASS_ATTR);
				// Get priority for new entry, if optional priority attribute specified
				int priority = getPriority(configElements[i], CONTRIBUTION_WARNING, protocol);
				String contributorName = configElements[i].getDeclaringExtension().getContributor().getName();
				// Now create new ProtocolFactory
				ProtocolFactory newProtocolFactory = new ProtocolFactory(clazz, priority, contributorName);
				// Then look for any existing protocol factories under same protocol
				synchronized (retrieveFileTransferProtocolMap) {
					ProtocolFactory oldProtocolFactory = (ProtocolFactory) retrieveFileTransferProtocolMap.get(protocol);
					// If found, choose between them based upon comparing their priority
					if (oldProtocolFactory != null) {
						// Now, compare priorities and pic winner
						int result = oldProtocolFactory.compareTo(newProtocolFactory);
						if (result < 0) {
							// Existing one has higher priority, so we provide warning and return (leaving existing one as the handler)
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_EXISTING_HIGHER_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName}), null));
							continue;
						} else if (result == 0) {
							// Warn that we are using new one because they have the same priority.
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_SAME_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName, new Integer(priority)}), null));
						} else if (result > 0) {
							// Warn that we are using new one because it has higher priority.
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_NEW_HIGHER_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName, new Integer(priority), new Integer(oldProtocolFactory.priority)}), null));
						}
					}
					if (!isSchemeRegistered(protocol, existingSchemes))
						registerScheme(protocol);
					// Finally, put clazz in map with protocol as key
					retrieveFileTransferProtocolMap.put(protocol, newProtocolFactory);
				}
			} catch (final CoreException e) {
				Activator.getDefault().log(new Status(IStatus.ERROR, PLUGIN_ID, IStatus.ERROR, NLS.bind(Messages.Activator_EXCEPTION_LOADING_EXTENSION_POINT, RETRIEVE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT), e));
			}
		}
	}

	void removeRetrieveExtensions(IConfigurationElement[] configElements) {
		for (int i = 0; i < configElements.length; i++) {
			final String protocol = configElements[i].getAttribute(PROTOCOL_ATTR);
			if (protocol == null || "".equals(protocol)) //$NON-NLS-1$
				return;
			synchronized (retrieveFileTransferProtocolMap) {
				ProtocolFactory protocolFactory = (ProtocolFactory) retrieveFileTransferProtocolMap.get(protocol);
				if (protocolFactory != null) {
					// If the contributor that is leaving is the one responsible for the protocol factory then remove
					if (configElements[i].getContributor().getName().equals(protocolFactory.getID())) {
						retrieveFileTransferProtocolMap.remove(protocol);
					}
				}
			}
		}
	}

	void addSendExtensions(IConfigurationElement[] configElements) {
		String[] existingSchemes = getPlatformSupportedSchemes();
		for (int i = 0; i < configElements.length; i++) {
			final String protocol = configElements[i].getAttribute(PROTOCOL_ATTR);
			if (protocol == null || "".equals(protocol)) //$NON-NLS-1$
				return;
			String CONTRIBUTION_WARNING = Messages.Activator_WARNING_SEND_CONTRIBUTION_PREFIX;
			try {
				// First create factory clazz 
				final ISendFileTransferFactory clazz = (ISendFileTransferFactory) configElements[i].createExecutableExtension(CLASS_ATTR);
				// Get priority for new entry, if optional priority attribute specified
				int priority = getPriority(configElements[i], CONTRIBUTION_WARNING, protocol);
				String contributorName = configElements[i].getDeclaringExtension().getContributor().getName();
				// Now create new ProtocolFactory
				ProtocolFactory newProtocolFactory = new ProtocolFactory(clazz, priority, contributorName);
				// Then look for any existing protocol factories under same protocol
				synchronized (sendFileTransferProtocolMap) {
					ProtocolFactory oldProtocolFactory = (ProtocolFactory) sendFileTransferProtocolMap.get(protocol);
					// If found, choose between them based upon comparing their priority
					if (oldProtocolFactory != null) {
						// Now, compare priorities and pic winner
						int result = oldProtocolFactory.compareTo(newProtocolFactory);
						if (result < 0) {
							// Existing one has higher priority, so we provide warning and return (leaving existing one as the handler)
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_EXISTING_HIGHER_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName}), null));
							continue;
						} else if (result == 0) {
							// Warn that we are using new one because they have the same priority.
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_SAME_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName, new Integer(priority)}), null));
						} else if (result > 0) {
							// Warn that we are using new one because it has higher priority.
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_NEW_HIGHER_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName, new Integer(priority), new Integer(oldProtocolFactory.priority)}), null));
						}
					}
					if (!isSchemeRegistered(protocol, existingSchemes))
						registerScheme(protocol);
					// Finally, put clazz in map with protocol as key
					sendFileTransferProtocolMap.put(protocol, newProtocolFactory);
				}
			} catch (final CoreException e) {
				Activator.getDefault().log(new Status(IStatus.ERROR, PLUGIN_ID, IStatus.ERROR, NLS.bind(Messages.Activator_EXCEPTION_LOADING_EXTENSION_POINT, SEND_FILETRANSFER_PROTOCOL_FACTORY_EPOINT), e));
			}
		}
	}

	void removeSendExtensions(IConfigurationElement[] configElements) {
		for (int i = 0; i < configElements.length; i++) {
			final String protocol = configElements[i].getAttribute(PROTOCOL_ATTR);
			if (protocol == null || "".equals(protocol)) //$NON-NLS-1$
				return;
			synchronized (sendFileTransferProtocolMap) {
				ProtocolFactory protocolFactory = (ProtocolFactory) sendFileTransferProtocolMap.get(protocol);
				if (protocolFactory != null) {
					// If the contributor that is leaving is the one responsible for the protocol factory then remove
					if (configElements[i].getContributor().getName().equals(protocolFactory.getID())) {
						sendFileTransferProtocolMap.remove(protocol);
					}
				}
			}
		}
	}

	void addBrowseExtensions(IConfigurationElement[] configElements) {
		String[] existingSchemes = getPlatformSupportedSchemes();
		for (int i = 0; i < configElements.length; i++) {
			final String protocol = configElements[i].getAttribute(PROTOCOL_ATTR);
			if (protocol == null || "".equals(protocol)) //$NON-NLS-1$
				return;
			String CONTRIBUTION_WARNING = Messages.Activator_WARNING_BROWSE_CONTRIBUTION_PREFIX;
			try {
				// First create factory clazz 
				final IRemoteFileSystemBrowserFactory clazz = (IRemoteFileSystemBrowserFactory) configElements[i].createExecutableExtension(CLASS_ATTR);
				// Get priority for new entry, if optional priority attribute specified
				int priority = getPriority(configElements[i], CONTRIBUTION_WARNING, protocol);
				String contributorName = configElements[i].getDeclaringExtension().getContributor().getName();
				// Now create new ProtocolFactory
				ProtocolFactory newProtocolFactory = new ProtocolFactory(clazz, priority, contributorName);
				synchronized (browseFileTransferProtocolMap) {
					// Then look for any existing protocol factories under same protocol
					ProtocolFactory oldProtocolFactory = (ProtocolFactory) browseFileTransferProtocolMap.get(protocol);
					// If found, choose between them based upon comparing their priority
					if (oldProtocolFactory != null) {
						// Now, compare priorities and pic winner
						int result = oldProtocolFactory.compareTo(newProtocolFactory);
						if (result < 0) {
							// Existing one has higher priority, so we provide warning and return (leaving existing one as the handler)
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_EXISTING_HIGHER_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName}), null));
							continue;
						} else if (result == 0) {
							// Warn that we are using new one because they have the same priority.
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_SAME_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName, new Integer(priority)}), null));
						} else if (result > 0) {
							// Warn that we are using new one because it has higher priority.
							Activator.getDefault().log(new Status(IStatus.WARNING, PLUGIN_ID, IStatus.WARNING, NLS.bind(Messages.Activator_WARNING_NEW_HIGHER_PRIORITY, new Object[] {CONTRIBUTION_WARNING, protocol, contributorName, new Integer(priority), new Integer(oldProtocolFactory.priority)}), null));
						}
					}
					if (!isSchemeRegistered(protocol, existingSchemes))
						registerScheme(protocol);
					// Finally, put clazz in map with protocol as key
					browseFileTransferProtocolMap.put(protocol, newProtocolFactory);
				}
			} catch (final CoreException e) {
				Activator.getDefault().log(new Status(IStatus.ERROR, PLUGIN_ID, IStatus.ERROR, NLS.bind(Messages.Activator_EXCEPTION_LOADING_EXTENSION_POINT, BROWSE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT), e));
			}
		}
	}

	void removeBrowseExtensions(IConfigurationElement[] configElements) {
		for (int i = 0; i < configElements.length; i++) {
			final String protocol = configElements[i].getAttribute(PROTOCOL_ATTR);
			if (protocol == null || "".equals(protocol)) //$NON-NLS-1$
				return;
			synchronized (browseFileTransferProtocolMap) {
				ProtocolFactory protocolFactory = (ProtocolFactory) browseFileTransferProtocolMap.get(protocol);
				if (protocolFactory != null) {
					// If the contributor that is leaving is the one responsible for the protocol factory then remove
					if (configElements[i].getContributor().getName().equals(protocolFactory.getID())) {
						browseFileTransferProtocolMap.remove(protocol);
					}
				}
			}
		}
	}

	private void loadProtocolHandlers() {
		this.retrieveFileTransferProtocolMap = new HashMap(3);
		this.sendFileTransferProtocolMap = new HashMap(3);
		this.browseFileTransferProtocolMap = new HashMap(3);
		final IExtensionRegistry reg = getExtensionRegistry();
		if (reg != null) {
			final IExtensionPoint retrieveExtensionPoint = reg.getExtensionPoint(RETRIEVE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT);
			if (retrieveExtensionPoint != null)
				addRetrieveExtensions(retrieveExtensionPoint.getConfigurationElements());
			// Now do it with send
			final IExtensionPoint sendExtensionPoint = reg.getExtensionPoint(SEND_FILETRANSFER_PROTOCOL_FACTORY_EPOINT);
			if (sendExtensionPoint != null)
				addSendExtensions(sendExtensionPoint.getConfigurationElements());
			// Now for browse
			final IExtensionPoint browseExtensionPoint = reg.getExtensionPoint(BROWSE_FILETRANSFER_PROTOCOL_FACTORY_EPOINT);
			if (browseExtensionPoint != null)
				addBrowseExtensions(browseExtensionPoint.getConfigurationElements());
		}
	}

	private boolean isSchemeRegistered(String protocol, String[] schemes) {
		for (int i = 0; i < schemes.length; i++) {
			if (protocol.equals(schemes[i]))
				return true;
		}
		return false;
	}

	class DummyURLStreamHandlerService extends AbstractURLStreamHandlerService {

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.osgi.service.url.AbstractURLStreamHandlerService#openConnection(java.net.URL)
		 */
		public URLConnection openConnection(URL u) throws IOException {
			throw new IOException(NLS.bind(Messages.Activator_EXCEPTION_URLConnection_CANNOT_BE_CREATED, u.toExternalForm()));
		}

	}

	private final DummyURLStreamHandlerService dummyService = new DummyURLStreamHandlerService();

	private void registerScheme(String protocol) {
		final Hashtable properties = new Hashtable();
		properties.put(URLConstants.URL_HANDLER_PROTOCOL, new String[] {protocol});
		context.registerService(URLStreamHandlerService.class.getName(), dummyService, properties);
	}

	public IRetrieveFileTransfer getFileTransfer(String protocol) {
		ProtocolFactory protocolFactory = null;
		synchronized (retrieveFileTransferProtocolMap) {
			protocolFactory = (ProtocolFactory) retrieveFileTransferProtocolMap.get(protocol);
		}
		if (protocolFactory == null)
			return null;
		final IRetrieveFileTransferFactory factory = (IRetrieveFileTransferFactory) protocolFactory.getFactory();
		if (factory != null)
			return factory.newInstance();
		return null;
	}

	public ISendFileTransfer getSendFileTransfer(String protocol) {
		ProtocolFactory protocolFactory = null;
		synchronized (sendFileTransferProtocolMap) {
			protocolFactory = (ProtocolFactory) sendFileTransferProtocolMap.get(protocol);
		}
		if (protocolFactory == null)
			return null;
		final ISendFileTransferFactory factory = (ISendFileTransferFactory) protocolFactory.getFactory();
		if (factory != null)
			return factory.newInstance();
		return null;
	}

	public IRemoteFileSystemBrowser getBrowseFileTransfer(String protocol) {
		ProtocolFactory protocolFactory = null;
		synchronized (browseFileTransferProtocolMap) {
			protocolFactory = (ProtocolFactory) browseFileTransferProtocolMap.get(protocol);
		}
		if (protocolFactory == null)
			return null;
		final IRemoteFileSystemBrowserFactory factory = (IRemoteFileSystemBrowserFactory) protocolFactory.getFactory();
		if (factory != null)
			return factory.newInstance();
		return null;
	}

	public IAdapterManager getAdapterManager() {
		// First, try to get the adapter manager via
		if (adapterManagerTracker == null) {
			adapterManagerTracker = new ServiceTracker(this.context, IAdapterManager.class.getName(), null);
			adapterManagerTracker.open();
		}
		IAdapterManager adapterManager = (IAdapterManager) adapterManagerTracker.getService();
		// Then, if the service isn't there, try to get from Platform class via
		// PlatformHelper class
		if (adapterManager == null)
			adapterManager = PlatformHelper.getPlatformAdapterManager();
		return adapterManager;
	}

}
