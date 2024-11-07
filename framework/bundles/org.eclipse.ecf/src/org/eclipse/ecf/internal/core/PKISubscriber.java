package org.eclipse.ecf.internal.core;

import java.lang.reflect.*;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Flow.Subscriber;
import java.util.concurrent.Flow.Subscription;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;

public class PKISubscriber implements Subscriber {

	SSLContext sslContext = null;

	public PKISubscriber() {
	}

	public void onSubscribe(Subscription subscription) {
		// TODO Auto-generated method stub
	}

	public void onNext(Object item) {
		// TODO Auto-generated method stub
		try {
			TimeUnit.SECONDS.sleep(5);
			Class pkiClass = Class.forName("org.eclipse.core.pki.auth.KeystoreSetup"); //$NON-NLS-1$
			Constructor pkiConstructor = pkiClass.getDeclaredConstructor();
			pkiConstructor.setAccessible(true);
			Object pkiManager = pkiClass.getDeclaredConstructor().newInstance();
			Method method = pkiManager.getClass().getMethod("isKeyStoreLoaded");//$NON-NLS-1$
			boolean result1 = (Boolean) method.invoke(pkiManager);
			if (result1) {
				//TimeUnit.SECONDS.sleep(5);
				Method sslMethod = pkiManager.getClass().getMethod("getSSLContext");//$NON-NLS-1$
				sslContext = (SSLContext) sslMethod.invoke(pkiManager);
				if (sslContext == null) {
					sslContext = SSLContext.getDefault();
				} else {
					SSLContext.setDefault(sslContext);
				}
			}
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			//System.out.println("PKISubscriber  No Keystore FOUND");
			// There was no PKI core installed
		} catch (InstantiationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void onError(Throwable throwable) {
		// TODO Auto-generated method stub
	}

	@Override
	public void onComplete() {
		// TODO Auto-generated method stub
	}
}
