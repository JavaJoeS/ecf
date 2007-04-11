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

package org.eclipse.ecf.internal.provider.filetransfer;

import org.eclipse.osgi.util.NLS;

/**
 * 
 */
public class Messages extends NLS {
	private static final String BUNDLE_NAME = "org.eclipse.ecf.internal.provider.filetransfer.messages"; //$NON-NLS-1$
	public static String AbstractRetrieveFileTransfer_MalformedURLException;
	public static String AbstractRetrieveFileTransfer_Progress_Data;
	public static String AbstractRetrieveFileTransfer_Exception_User_Cancelled;
	public static String AbstractRetrieveFileTransfer_RemoteFileID_Not_Null;
	public static String AbstractRetrieveFileTransfer_Status_Transfer_Completed_OK;
	public static String AbstractRetrieveFileTransfer_Status_Transfer_Exception;
	public static String AbstractRetrieveFileTransfer_TransferListener_Not_Null;
	public static String Activator_EXCEPTION_URLConnection_CANNOT_BE_CREATED;
	public static String FileTransferNamespace_Exception_Args_Null;
	public static String FileTransferNamespace_Exception_Create_Instance;
	public static String FileTransferNamespace_Exception_Create_Instance_Failed;
	public static String FileTransferNamespace_File_Protocol;
	public static String FileTransferNamespace_Ftp_Protocol;
	public static String FileTransferNamespace_Http_Protocol;
	public static String FileTransferNamespace_Https_Protocol;
	public static String FileTransferNamespace_Jar_Protocol;
	public static String FileTransferNamespace_Mailto_Protocol;
	public static String FileTransferNamespace_Gopher_Protocol;
	public static String FileTransferNamespace_Namespace_Protocol;
	public static String HttpClientRetrieveFileTransfer_Http_ProxyHost_Prop;
	public static String HttpClientRetrieveFileTransfer_Http_ProxyPort_Prop;
	public static String HttpClientRetrieveFileTransfer_Proxy_Auth_Required;
	public static String HttpClientRetrieveFileTransfer_Unauthorized;
	public static String HttpClientRetrieveFileTransfer_Username_Prefix;
	public static String FileTransferID_Exception_Url_Not_Null;
	public static String SslProtocolSocketFactory_SSLContext_Instance;
	public static String SslProtocolSocketFactory_Status_Create_Error;

	static {
		// initialize resource bundle
		NLS.initializeMessages(BUNDLE_NAME, Messages.class);
	}

	private Messages() {
	}
}
