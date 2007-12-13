/****************************************************************************
 * Copyright (c) 2007 Composent, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Composent, Inc. - initial API and implementation
 *****************************************************************************/

package org.eclipse.ecf.internal.provider.filetransfer.scp;

import com.jcraft.jsch.*;
import java.io.*;
import java.net.URL;
import java.util.Map;
import org.eclipse.ecf.core.security.IConnectContext;
import org.eclipse.ecf.core.util.Proxy;
import org.eclipse.ecf.filetransfer.IIncomingFileTransferRequestListener;
import org.eclipse.ecf.filetransfer.SendFileTransferException;
import org.eclipse.ecf.filetransfer.service.ISendFileTransfer;
import org.eclipse.ecf.provider.filetransfer.outgoing.AbstractOutgoingFileTransfer;
import org.eclipse.osgi.util.NLS;

/**
 *
 */
public class ScpOutgoingFileTransfer extends AbstractOutgoingFileTransfer implements ISendFileTransfer, IScpFileTransfer {

	private static final String SCP_COMMAND = "scp -p -t "; //$NON-NLS-1$
	private static final String SCP_EXEC = "exec"; //$NON-NLS-1$

	String username;

	private Channel channel;

	private InputStream responseStream;
	private IConnectContext connectContext;

	private ScpUtil scpUtil;

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.provider.filetransfer.outgoing.AbstractOutgoingFileTransfer#openStreams()
	 */
	protected void openStreams() throws SendFileTransferException {
		try {
			final File localFile = getFileTransferInfo().getFile();
			// Set input stream from local file
			setInputStream(new BufferedInputStream(new FileInputStream(localFile)));
			final URL url = getRemoteFileURL();
			this.username = (url.getUserInfo() == null) ? System.getProperty("user.name") : url.getUserInfo(); //$NON-NLS-1$
			scpUtil = new ScpUtil(this);
			final Session s = scpUtil.getSession();
			s.connect();
			final String targetFileName = scpUtil.trimTargetFile(url.getPath());
			final String command = SCP_COMMAND + targetFileName;
			channel = s.openChannel(SCP_EXEC);
			((ChannelExec) channel).setCommand(command);
			final OutputStream outs = channel.getOutputStream();
			responseStream = channel.getInputStream();
			channel.connect();
			scpUtil.checkAck(responseStream);
			sendFileNameAndSize(localFile, targetFileName, outs, responseStream);
			setOutputStream(outs);
			fireSendStartEvent();
		} catch (final Exception e) {
			throw new SendFileTransferException(NLS.bind(Messages.ScpOutgoingFileTransfer_EXCEPTION_CONNECTING, getRemoteFileURL().toString()), e);
		}

	}

	public Map getOptions() {
		return options;
	}

	public URL getTargetURL() {
		return getRemoteFileURL();
	}

	public Proxy getProxy() {
		return this.proxy;
	}

	private void sendFileNameAndSize(File localFile, String fileName, OutputStream outs, InputStream ins) throws IOException {
		// send "C0644 filesize filename", where filename should not include '/'
		final long filesize = localFile.length();
		final StringBuffer command = new StringBuffer("C0644 "); //$NON-NLS-1$
		command.append(filesize).append(" ").append(fileName).append("\n"); //$NON-NLS-1$ //$NON-NLS-2$
		outs.write(command.toString().getBytes());
		outs.flush();
		scpUtil.checkAck(ins);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.provider.filetransfer.outgoing.AbstractOutgoingFileTransfer#hardClose()
	 */
	protected void hardClose() {
		try {
			if (scpUtil != null) {
				scpUtil.sendZeroToStream(remoteFileContents);
				scpUtil.checkAck(responseStream);
			}
			if (remoteFileContents != null) {
				remoteFileContents.close();
				remoteFileContents = null;
			}
			if (channel != null) {
				channel.disconnect();
				channel = null;
			}
			if (scpUtil != null) {
				scpUtil.dispose();
				scpUtil = null;
			}
		} catch (final IOException e) {
			exception = e;
		}
		username = null;
		super.hardClose();
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.provider.filetransfer.outgoing.AbstractOutgoingFileTransfer#setupProxy(org.eclipse.ecf.core.util.Proxy)
	 */
	protected void setupProxy(Proxy proxy) {
		this.proxy = proxy;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.filetransfer.ISendFileTransferContainerAdapter#addListener(org.eclipse.ecf.filetransfer.IIncomingFileTransferRequestListener)
	 */
	public void addListener(IIncomingFileTransferRequestListener l) {
		// SCP doesn't have listener
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.filetransfer.ISendFileTransferContainerAdapter#removeListener(org.eclipse.ecf.filetransfer.IIncomingFileTransferRequestListener)
	 */
	public boolean removeListener(IIncomingFileTransferRequestListener l) {
		return false;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.filetransfer.ISendFileTransferContainerAdapter#setConnectContextForAuthentication(org.eclipse.ecf.core.security.IConnectContext)
	 */
	public void setConnectContextForAuthentication(IConnectContext connectContext) {
		this.connectContext = connectContext;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.filetransfer.ISendFileTransferContainerAdapter#setProxy(org.eclipse.ecf.core.util.Proxy)
	 */
	public void setProxy(Proxy proxy) {
		this.proxy = proxy;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.provider.filetransfer.scp.IScpFileTransfer#getConnectContext()
	 */
	public IConnectContext getConnectContext() {
		return connectContext;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ecf.provider.filetransfer.scp.IScpFileTransfer#getUsername()
	 */
	public String getUsername() {
		return username;
	}

}
