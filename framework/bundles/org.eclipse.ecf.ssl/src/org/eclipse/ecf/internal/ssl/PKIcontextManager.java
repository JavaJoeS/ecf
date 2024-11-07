package org.eclipse.ecf.internal.ssl;

import java.lang.reflect.*;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import org.osgi.framework.*;
import org.osgi.util.tracker.ServiceTracker;

public class PKIcontextManager implements BundleActivator {

	private static PKIcontextManager INSTANCE = null;
	private static volatile BundleContext context;
	private SSLContext sslContext;
	private volatile ServiceTracker keyManagerTracker = null;
	private ServiceRegistration pkiFactoryRegistration;
	protected final String corePKI = "org.eclipse.core.pki.auth.KeystoreSetup";//$NON-NLS-1$

	public static PKIcontextManager getInstance() {
		try {
			if (INSTANCE == null) {
				INSTANCE = new PKIcontextManager();
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return INSTANCE;
	}

	public void setSSLContext(SSLContext sslContext) {
		this.sslContext = sslContext;
	}

	public SSLContext getSSLContext() {
		if (sslContext == null) {

			try {

				Class pkiClass = Class.forName(corePKI);
				Constructor[] constructors = pkiClass.getDeclaredConstructors();
				Constructor<?> privateConstructor = constructors[0];
				privateConstructor.setAccessible(true);

				Object pkiManager = privateConstructor.newInstance();
				Method myInstance = pkiClass.getDeclaredMethod("getInstance", null);//$NON-NLS-1$

				Object myObject = myInstance.invoke(pkiManager);

				Method method = pkiManager.getClass().getMethod("isKeyStoreLoaded");//$NON-NLS-1$
				boolean result = (Boolean) method.invoke(pkiManager, null);
				if (result) {
					Method sslMethod = pkiManager.getClass().getDeclaredMethod("getSSLContext");//$NON-NLS-1$
					sslContext = (SSLContext) sslMethod.invoke(pkiManager, null);

					if (sslContext == null) {
						sslContext = SSLContext.getDefault(); // default too
					}
				}

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
				// Its OK, org.eclipse.core.pki may not have been installed
			} catch (NoSuchMethodException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InstantiationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return sslContext;
	}

	public void start(BundleContext context) throws Exception {
		// TODO Auto-generated method stub
		PKIcontextManager.context = context;

	}

	public void stop(BundleContext context) throws Exception {
		// TODO Auto-generated method stub
		if (pkiFactoryRegistration != null) {
			pkiFactoryRegistration.unregister();
			pkiFactoryRegistration = null;
		}
		if (keyManagerTracker != null) {
			keyManagerTracker.close();
			keyManagerTracker = null;
		}
		PKIcontextManager.context = null;
	}

}
