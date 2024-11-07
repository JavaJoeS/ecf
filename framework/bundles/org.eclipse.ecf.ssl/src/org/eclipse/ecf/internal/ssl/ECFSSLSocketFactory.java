/****************************************************************************
 * Copyright (c)2008 IBM Corporation and others.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *
 * SPDX-License-Identifier: EPL-2.0
 *****************************************************************************/
package org.eclipse.ecf.internal.ssl;

import java.io.IOException;
import java.net.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class ECFSSLSocketFactory extends SSLSocketFactory {

	public static final String DEFAULT_SSL_PROTOCOL = "https.protocols"; //$NON-NLS-1$

	private SSLContext sslContext = null;

	private String defaultProtocolNames = System.getProperty(DEFAULT_SSL_PROTOCOL);

	private SSLSocketFactory getSSLSocketFactory() throws IOException {
		try {
			PKIcontextManager manager = PKIcontextManager.getInstance();
			sslContext = manager.getSSLContext();
			// if (sslContext != null) {
			// System.out.println("ECFSSLSocketFactory getSSLSocketFactory GOT
			// SOCKET from Manager call");
			// } else {
			// System.out.println("ECFSSLSocketFactory getSSLSocketFactory NULL
			// SSLContext");
			// }
		} catch (Exception e) {
			// might not be set up right or even installed see
			// org.eclipse.core.pki
		}
		if (null == sslContext) {
			try {
				sslContext = getSSLContext(defaultProtocolNames);
			} catch (Exception e) {
				IOException ioe = new IOException();
				ioe.initCause(e);
				throw ioe;
			}
		}
		return (sslContext == null) ? (SSLSocketFactory) SSLSocketFactory.getDefault() : sslContext.getSocketFactory();
	}

	public SSLContext getSSLContext(String protocols) {
		return SSLContextHelper.getSSLContext(protocols);
	}

	public Socket createSocket() throws IOException {
		return getSSLSocketFactory().createSocket();
	}

	public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
		return getSSLSocketFactory().createSocket(socket, host, port, autoClose);
	}

	public String[] getDefaultCipherSuites() {
		try {
			return getSSLSocketFactory().getDefaultCipherSuites();
		} catch (IOException e) {
			return new String[] {};
		}
	}

	public String[] getSupportedCipherSuites() {
		try {
			return getSSLSocketFactory().getSupportedCipherSuites();
		} catch (IOException e) {
			return new String[] {};
		}
	}

	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
		return getSSLSocketFactory().createSocket(host, port);
	}

	public Socket createSocket(InetAddress address, int port) throws IOException {
		return getSSLSocketFactory().createSocket(address, port);
	}

	public Socket createSocket(InetAddress address, int port, InetAddress arg2, int arg3) throws IOException {
		return getSSLSocketFactory().createSocket(address, port);
	}

	public Socket createSocket(String host, int port, InetAddress address, int localPort)
			throws IOException, UnknownHostException {
		return getSSLSocketFactory().createSocket(host, port, address, localPort);
	}

}
