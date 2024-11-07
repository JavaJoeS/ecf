package org.eclipse.ecf.internal.core;

import java.lang.reflect.*;
import java.util.concurrent.Flow.Subscriber;
import java.util.concurrent.TimeUnit;

public class LazyPKISubscriber implements Runnable {

	public static final String publisherUpdate = "org.eclipse.core.pki.auth.PublishPasswordUpdate";//$NON-NLS-1$

	@Override
	public void run() {
		// TODO Auto-generated method stub
		try {
			//System.out.println(" LazyPKISubscriber NOW SLEEP");
			TimeUnit.SECONDS.sleep(8);
			//System.out.println(" LazyPKISubscriber AWAKE");
			PKISubscriber subscriber = new PKISubscriber();

			Object instance = Class.forName(publisherUpdate).getDeclaredConstructor().newInstance();
			Method myInstance = instance.getClass().getDeclaredMethod("getInstance", null);//$NON-NLS-1$
			Object myObject = myInstance.invoke(instance);

			Method methodSub = instance.getClass().getDeclaredMethod("subscribe", Subscriber.class);//$NON-NLS-1$
			methodSub.invoke(instance, subscriber);

			Class pubClass = Class.forName(publisherUpdate);
			Constructor constructor = pubClass.getDeclaredConstructor();
			constructor.setAccessible(true);
			Object obj = constructor.newInstance();

			Method theInstance = pubClass.getDeclaredMethod("getInstance", null);//$NON-NLS-1$
			Object theObject = theInstance.invoke(obj);

			Method mo = theObject.getClass().getDeclaredMethod("subscribe", Subscriber.class);//$NON-NLS-1$
			mo.invoke(theObject, subscriber);
		} catch (InterruptedException e) {
			System.out.println("Thread is interuppted....");//$NON-NLS-1$
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
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			//  PKI core was not loaded and configured
		}
	}
}
