/*******************************************************************************
 * Copyright (c) 2015 Composent, Inc. All rights reserved. This
 * program and the accompanying materials are made available under the terms of
 * the Eclipse Public License v1.0 which accompanies this distribution, and is
 * available at http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors: Scott Lewis - initial API and implementation
 ******************************************************************************/
package org.eclipse.ecf.remoteserviceadmin.ui.rsa;

import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.ecf.internal.remoteservices.ui.Activator;
import org.eclipse.ecf.internal.remoteservices.ui.DiscoveryComponent;
import org.eclipse.ecf.osgi.services.remoteserviceadmin.RemoteServiceAdmin;
import org.eclipse.ecf.remoteserviceadmin.ui.rsa.model.AbstractRSAContentProvider;
import org.eclipse.ecf.remoteserviceadmin.ui.rsa.model.AbstractRSANode;
import org.eclipse.ecf.remoteserviceadmin.ui.rsa.model.ExportRegistrationNode;
import org.eclipse.ecf.remoteserviceadmin.ui.rsa.model.ImportRegistrationNode;
import org.eclipse.ecf.remoteserviceadmin.ui.service.ServicesView;
import org.eclipse.jface.action.IMenuListener;
import org.eclipse.jface.action.IMenuManager;
import org.eclipse.jface.action.MenuManager;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.viewers.ISelectionChangedListener;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.viewers.ITreeSelection;
import org.eclipse.jface.viewers.SelectionChangedEvent;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.ui.IViewPart;
import org.eclipse.ui.IViewSite;
import org.eclipse.ui.IWorkbenchPage;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.model.WorkbenchLabelProvider;
import org.eclipse.ui.part.ViewPart;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;

/**
 * @since 3.3
 */
public abstract class AbstractRemoteServiceAdminView extends ViewPart {

	protected TreeViewer viewer;
	protected AbstractRSAContentProvider contentProvider;

	public AbstractRemoteServiceAdminView() {
		super();
	}

	protected RemoteServiceAdmin getLocalRSA() {
		DiscoveryComponent discovery = DiscoveryComponent.getDefault();
		return (discovery == null) ? null : discovery.getRSA();
	}

	protected void fillContextMenu(IMenuManager manager) {

	}

	protected void makeActions() {

	}

	protected void hookContextMenu() {
		MenuManager menuMgr = new MenuManager("#PopupMenu"); //$NON-NLS-1$
		menuMgr.setRemoveAllWhenShown(true);
		menuMgr.addMenuListener(new IMenuListener() {
			public void menuAboutToShow(IMenuManager manager) {
				AbstractRemoteServiceAdminView.this.fillContextMenu(manager);
			}
		});
		Menu menu = menuMgr.createContextMenu(viewer.getControl());
		viewer.getControl().setMenu(menu);
		getSite().registerContextMenu(menuMgr, viewer);
	}

	protected AbstractRSANode getSelectedNode() {
		return ((AbstractRSANode) ((ITreeSelection) viewer.getSelection()).getFirstElement());
	}

	@Override
	public void dispose() {
		super.dispose();
		viewer = null;
		contentProvider = null;
	}

	protected abstract AbstractRSAContentProvider createContentProvider(IViewSite viewSite);

	protected void updateModel() {
	}

	protected abstract void setupListeners();

	protected void log(int level, String message, Throwable e) {
		Activator.getDefault().getLog().log(new Status(level, Activator.PLUGIN_ID, message, e));
	}

	protected void logWarning(String message, Throwable e) {
		log(IStatus.WARNING, message, e);
	}

	protected void logError(String message, Throwable e) {
		log(IStatus.ERROR, message, e);
	}

	protected void selectServiceInServicesView(final long serviceId) {
		try {
			IWorkbenchWindow window = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
			if (window != null) {
				IWorkbenchPage page = window.getActivePage();
				if (page != null) {
					IViewPart view = page.findView(ServicesView.ID_VIEW); //$NON-NLS-1$
					if (view != null)
						((ServicesView) view).setSelectedService(serviceId);
				}
			}
		} catch (Exception e) {
			logWarning("Could not show services in PDE Plugin view", e); //$NON-NLS-1$
		}
	}
	
	protected void addSelectionListeners() {
		viewer.addSelectionChangedListener(new ISelectionChangedListener() {
			@Override
			public void selectionChanged(SelectionChangedEvent event) {
				ISelection sel = event.getSelection();
				Object selection = null;
				if (sel instanceof IStructuredSelection)
					selection = ((IStructuredSelection) sel).getFirstElement();
				ServiceReference sr = null;
				if (selection instanceof ExportRegistrationNode) {
					sr = ((ExportRegistrationNode) selection).getServiceReference();
				} else if (selection instanceof ImportRegistrationNode) {
					sr = ((ImportRegistrationNode) selection).getServiceReference();
				}
				if (sr != null) 
					selectServiceInServicesView((Long) sr.getProperty(Constants.SERVICE_ID));
			}
		});
	}
	
	@Override
	public void createPartControl(Composite parent) {

		IViewSite viewSite = getViewSite();

		this.contentProvider = createContentProvider(viewSite);

		viewer = new TreeViewer(parent, SWT.MULTI | SWT.H_SCROLL | SWT.V_SCROLL);
		viewer.setContentProvider(this.contentProvider);
		viewer.setLabelProvider(new WorkbenchLabelProvider());
		viewer.setAutoExpandLevel(TreeViewer.ALL_LEVELS);
		viewer.setInput(viewSite);

		makeActions();
		hookContextMenu();

		viewSite.setSelectionProvider(viewer);
		
		addSelectionListeners();
		setupListeners();

		RemoteServiceAdmin rsa = getLocalRSA();
		if (rsa != null)
			updateModel();
	}

	@Override
	public void setFocus() {
	}

}