package org.eclipse.ecf.discovery.ui.handlers;

import java.util.*;
import org.eclipse.core.runtime.Assert;
import org.eclipse.ecf.core.*;
import org.eclipse.ecf.core.identity.*;
import org.eclipse.ecf.core.security.IConnectContext;
import org.eclipse.ecf.core.util.AdapterContainerFilter;
import org.eclipse.ecf.discovery.IServiceInfo;
import org.eclipse.ecf.discovery.ui.views.IServiceAccessHandler;
import org.eclipse.ecf.internal.discovery.ui.Activator;
import org.eclipse.ecf.internal.discovery.ui.Messages;
import org.eclipse.ecf.remoteservice.*;
import org.eclipse.jface.action.*;
import org.osgi.framework.InvalidSyntaxException;

public abstract class AbstractRemoteServiceAccessHandler implements IServiceAccessHandler {

	protected static final IContributionItem[] EMPTY_CONTRIBUTION = {};

	protected static IContributionItem[] NOT_AVAILABLE_CONTRIBUTION;

	protected final AdapterContainerFilter containerFilter;

	protected IServiceInfo serviceInfo;

	public AbstractRemoteServiceAccessHandler() {
		containerFilter = new AdapterContainerFilter(IRemoteServiceContainerAdapter.class);
		final IAction containerNotAvailableAction = new Action() {
			public void run() {
				// Do nothing
			}
		};
		containerNotAvailableAction.setText(Messages.AbstractRemoteServiceAccessHandler_NOT_AVAILABLE_MENU_TEXT);
		containerNotAvailableAction.setEnabled(false);
		NOT_AVAILABLE_CONTRIBUTION = new IContributionItem[] {new ActionContributionItem(containerNotAvailableAction)};
	}

	private IContainerManager getContainerManager() {
		return Activator.getDefault().getContainerManager();
	}

	protected boolean isConnected(IContainer container) {
		if (container == null)
			return false;
		return (container.getConnectedID() == null);
	}

	protected boolean matchTargetNamespace(IContainer container, String targetNamespace) {
		final Namespace containerNamespace = container.getConnectNamespace();
		if (containerNamespace == null && targetNamespace == null)
			return true;
		return (containerNamespace.getName().equals(targetNamespace));
	}

	protected boolean matchServiceType(String service) {
		return Arrays.asList(this.serviceInfo.getServiceID().getServiceTypeID().getServices()).contains(service);
	}

	protected List getRemoteServiceContainerAdapters() {
		final List remoteServicesContainerAdapters = new ArrayList();
		final IContainerManager containerManager = getContainerManager();
		if (containerManager == null)
			return remoteServicesContainerAdapters;
		final IContainer[] containers = containerManager.getAllContainers();
		for (int i = 0; i < containers.length; i++) {
			if (containerFilter.match(containers[i]) && matchTargetNamespace(containers[i], getConnectNamespace())) {
				remoteServicesContainerAdapters.add(containerFilter.getMatchResult());
			}
		}
		return remoteServicesContainerAdapters;
	}

	protected String getContainerFactory() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_CONTAINER_FACTORY_PROPERTY);
	}

	protected String getRemoteServiceClass() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_OBJECTCLASS_PROPERTY);
	}

	protected String getConnectNamespace() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_CONNECT_ID_NAMESPACE_PROPERTY);
	}

	protected String getConnectID() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_CONNECT_ID_PROPERTY);
	}

	protected String getServiceNamespace() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_SERVICE_ID_NAMESPACE_PROPERTY);
	}

	protected String getServiceID() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_SERVICE_ID_PROPERTY);
	}

	protected String getFilter() {
		return this.serviceInfo.getServiceProperties().getPropertyString(Constants.DISCOVERY_FILTER_PROPERTY);
	}

	protected ID createID(String namespace, String value) throws IDCreateException {
		return IDFactory.getDefault().createID(namespace, value);
	}

	protected IContributionItem[] getContributionsForMatchingService() {
		// First get container manager...if we don't have one, then we're outta here
		final List remoteServicesContainerAdapters = getRemoteServiceContainerAdapters();
		// If we've got none, then we return 
		if (remoteServicesContainerAdapters.size() == 0)
			return NOT_AVAILABLE_CONTRIBUTION;
		// If we've got one, then we do our thing
		final List contributions = new ArrayList();
		for (final Iterator i = remoteServicesContainerAdapters.iterator(); i.hasNext();) {
			IRemoteServiceContainerAdapter adapter = (IRemoteServiceContainerAdapter) i.next();
			IContributionItem[] menuContributions = getContributionItemsForService(adapter);
			if (menuContributions == null)
				continue;
			for (int j = 0; j < menuContributions.length; j++)
				contributions.add(menuContributions[j]);
		}
		return (IContributionItem[]) contributions.toArray(new IContributionItem[] {});
	}

	public IContributionItem[] getContributionsForService(IServiceInfo svcInfo) {
		if (svcInfo == null)
			return EMPTY_CONTRIBUTION;
		this.serviceInfo = svcInfo;
		if (matchServiceType(Constants.DISCOVERY_SERVICE_TYPE))
			return getContributionsForMatchingService();
		return EMPTY_CONTRIBUTION;
	}

	protected IRemoteServiceReference[] getRemoteServiceReferences(IRemoteServiceContainerAdapter adapter) throws InvalidSyntaxException, IDCreateException {
		ID serviceID = null;
		String serviceNamespace = getServiceNamespace();
		String serviceid = getServiceID();
		if (serviceNamespace != null && serviceid != null) {
			serviceID = createID(serviceNamespace, serviceid);
		}
		return adapter.getRemoteServiceReferences(new ID[] {serviceID}, getRemoteServiceClass(), getFilter());
	}

	protected IContainer createContainer() throws ContainerCreateException {
		return ContainerFactory.getDefault().createContainer(getContainerFactory());
	}

	protected void connectContainer(IContainer container, ID connectTargetID, IConnectContext connectContext) throws ContainerConnectException {
		Assert.isNotNull(container);
		Assert.isNotNull(connectTargetID);
		container.connect(connectTargetID, connectContext);
	}

	/**
	 * @param adapter the IRemoteServiceContainerAdapter to use to lookup the {@link IRemoteServiceReference}.  Will not be <code>null</code>.
	 * @return IContributionItem the menu contribution items to be added to the menu.  May be <code>null</code>.  If <code>null</code> then no item is added to the
	 * menu.
	 */
	protected abstract IContributionItem[] getContributionItemsForService(final IRemoteServiceContainerAdapter adapter);

}
