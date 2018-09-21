package com.peikm.dexextractor;

import android.app.Application;

public class BaseApplication extends Application{
	public static String pkgName = null;
	public static String GetPkgName(){
		return pkgName;
	}

}
