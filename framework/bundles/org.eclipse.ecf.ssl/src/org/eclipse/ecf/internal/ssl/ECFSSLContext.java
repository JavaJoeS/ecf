package org.eclipse.ecf.internal.ssl;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Optional;
import javax.net.ssl.*;

public enum ECFSSLContext {
	SETUP;

	public SSLContext get() {
		SSLContext context = null;

		try {
			context = SSLContextHelper.getSSLContext("TLS");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Optional<String> keystoreContainer = null;
		Optional<String> truststoreContainer = null;
		Optional<String> keystoreContainerPw = null;
		Optional<String> keystoreContainerType = null;
		Optional<String> truststoreContainerPw = null;
		Optional<String> truststoreContainerType = null;
		KeyStore keyStore = null;
		KeyStore trustStore = null;

		try {
			keystoreContainer = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStore"));//$NON-NLS-1$
			keystoreContainerType = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreType"));//$NON-NLS-1$
			keystoreContainerPw = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"));//$NON-NLS-1$

			truststoreContainer = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStore"));//$NON-NLS-1$
			truststoreContainerPw = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStorePassword"));//$NON-NLS-1$
			truststoreContainerType = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStoreType"));//$NON-NLS-1$

			// If ALL of the PKI properties are not set, then return NULL
			if ((keystoreContainer.isEmpty()) || keystoreContainerType.isEmpty() || keystoreContainerPw.isEmpty()
					|| truststoreContainer.isEmpty() || truststoreContainerPw.isEmpty()
					|| truststoreContainerType.isEmpty()) {
				return null;
			}

			String keyStoreLocation = (String) keystoreContainer.get();
			String keyStoreType = (String) keystoreContainerType.get();
			String keyStorePassword = (String) keystoreContainerPw.get();

			String trustStoreLocation = (String) truststoreContainer.get();
			String trustStorePassword = (String) truststoreContainerPw.get();
			String trustStoreType = (String) truststoreContainerType.get();

			try {
				InputStream ki = Files.newInputStream(Paths.get(keyStoreLocation));
				keyStore = KeyStore.getInstance(keyStoreType);
				keyStore.load(ki, keyStorePassword.toCharArray());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(keyStore, keyStorePassword.toCharArray());
				context = SSLContext.getInstance("TLS");

				InputStream is = Files.newInputStream(Paths.get(trustStoreLocation));
				trustStore = KeyStore.getInstance(trustStoreType);
				trustStore.load(is, trustStorePassword.toCharArray());

				TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
				tmf.init(trustStore);

				context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
				SSLContext.setDefault(context);
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return context;
	}
}