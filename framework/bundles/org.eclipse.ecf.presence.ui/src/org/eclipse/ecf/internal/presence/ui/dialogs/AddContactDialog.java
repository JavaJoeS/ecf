/****************************************************************************
 * Copyright (c) 2007 Remy Suen and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Remy Suen <remy.suen@gmail.com> - initial API and implementation
 *****************************************************************************/
package org.eclipse.ecf.internal.presence.ui.dialogs;

import java.util.List;

import org.eclipse.ecf.internal.presence.ui.Messages;
import org.eclipse.ecf.presence.IPresenceContainerAdapter;
import org.eclipse.ecf.presence.ui.MultiRosterAccount;
import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.viewers.ComboViewer;
import org.eclipse.jface.viewers.ISelectionChangedListener;
import org.eclipse.jface.viewers.IStructuredContentProvider;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.viewers.SelectionChangedEvent;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

public class AddContactDialog extends Dialog {

	private ComboViewer accountsViewer;

	private Text accountText;

	private Text aliasText;

	private Button okBtn;

	private IPresenceContainerAdapter selection;

	private String accountID;

	private String alias;

	private Object input;

	public AddContactDialog(Shell parentShell) {
		super(parentShell);
	}

	private void addListeners() {
		accountText.addModifyListener(new ModifyListener() {
			public void modifyText(ModifyEvent e) {
				okBtn.setEnabled(selection != null
						&& !accountText.getText().equals("")); //$NON-NLS-1$
			}
		});

		accountsViewer
				.addSelectionChangedListener(new ISelectionChangedListener() {
					public void selectionChanged(SelectionChangedEvent e) {
						IStructuredSelection iss = (IStructuredSelection) e
								.getSelection();
						selection = ((MultiRosterAccount) iss.getFirstElement())
								.getPresenceContainerAdapter();
						okBtn.setEnabled(!accountText.getText().equals("")); //$NON-NLS-1$
					}
				});
	}

	protected void configureShell(Shell newShell) {
		super.configureShell(newShell);
		newShell.setText(Messages.AddContactDialog_DialogTitle);
	}

	protected void createButtonsForButtonBar(Composite parent) {
		super.createButtonsForButtonBar(parent);
		okBtn = getButton(IDialogConstants.OK_ID);
		okBtn.setEnabled(false);
	}

	protected Control createDialogArea(Composite parent) {
		parent = (Composite) super.createDialogArea(parent);
		parent.setLayout(new GridLayout(1, true));
		GridData data = new GridData(SWT.FILL, SWT.FILL, true, true);

		new Label(parent, SWT.BEGINNING)
				.setText(Messages.AddContactDialog_UserID);
		accountText = new Text(parent, SWT.SINGLE);
		accountText.setLayoutData(data);

		new Label(parent, SWT.BEGINNING)
				.setText(Messages.AddContactDialog_Alias);
		aliasText = new Text(parent, SWT.SINGLE);
		aliasText.setLayoutData(data);

		new Label(parent, SWT.BEGINNING)
				.setText(Messages.AddContactDialog_Account);
		accountsViewer = new ComboViewer(parent, SWT.READ_ONLY | SWT.BORDER);
		accountsViewer.getControl().setLayoutData(data);
		accountsViewer.setContentProvider(new IStructuredContentProvider() {
			public Object[] getElements(Object inputElement) {
				return ((List) inputElement).toArray();
			}

			public void dispose() {
			}

			public void inputChanged(Viewer viewer, Object oldInput,
					Object newInput) {
			}
		});
		accountsViewer.setLabelProvider(new LabelProvider() {
			public String getText(Object element) {
				MultiRosterAccount account = (MultiRosterAccount) element;
				return account.getContainer().getConnectedID().getName();
			}
		});
		accountsViewer.setInput(input);

		addListeners();

		return parent;
	}

	protected void okPressed() {
		accountID = accountText.getText();
		alias = accountText.getText();
		super.okPressed();
	}

	public IPresenceContainerAdapter getSelection() {
		return selection;
	}

	public String getAccountID() {
		return accountID;
	}

	public String getAlias() {
		return alias;
	}

	public void setInput(Object input) {
		this.input = input;
	}

}
