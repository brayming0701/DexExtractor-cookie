package com.peikm.dexextractor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.lang.reflect.Field;

import android.content.Context;
import android.util.Log;

import dalvik.system.DexFile;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import com.peikm.dexextractor.BaseApplication;
public class DexExtractor implements IXposedHookLoadPackage  {

	 // native方法在libnativelib.so库文件中实现  
    public native void dumpdex(int cookie);  
      
    // 内部类  
    class dumpThread implements Runnable {  
          
        int cookide;  
        public dumpThread(int cookide){  
              
            // 保存dex文件的mCookie值  
            this.cookide = cookide;  
        }  
      
        @Override  
        public void run() {  
              
            try {  
                  
                // 休眠5s 时间足够壳修复dex  
                Thread.sleep(5000);  
                  
            } catch (InterruptedException e) {  
                  
                e.printStackTrace();  
            }  
              
            // 从内存中dump出解密后的内存dex文件  
            dumpdex(cookide);  
        }  
    }  
  
    public LoadPackageParam mLpparam;
    @Override  
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {  
    	mLpparam = lpparam;
    	String pkgName = "com";//"cn.com.jyscPhone";
    	File file = new File("/data/local/tmp/packageName");
    	if(!file.exists()){
    		file.createNewFile();
    	}else{
    		FileReader fr = new FileReader(file);
    		BufferedReader bufReader = new BufferedReader(fr); 
    		pkgName = bufReader.readLine();
        	fr.close();
        	bufReader.close();
        	
    	}
    	if (mLpparam.packageName.equals(pkgName)){  
            
            XposedBridge.log("Loaded App:" + mLpparam.packageName);  
            // 加载动态库文件libnativelib.so  
            System.load("/data/data/com.peikm.dexextractor/lib/libnative.so");  
              
            // 对类dalvik.system.DexFile的方法loadDex进行java Hook操作  
            // 获取到需要脱壳apk解密dex文件加载后返回的mCookie值  
            // 根据mCookie值进行内存dex文件的dump操作  
            loadhooklib(mLpparam);  
        }  	

    }  
      
     private void loadhooklib(XC_LoadPackage.LoadPackageParam lpparam) {  
           
        // 对类dalvik.system.DexFile的方法loadDex进行dalvik模式下的java Hook操作  
        // /libcore/dalvik/src/main/java/dalvik/system/DexFile.java  
        // static public DexFile loadDex(String sourcePathName, String outputPathName, int flags)  
        // http://androidxref.com/4.4.4_r1/xref/libcore/dalvik/src/main/java/dalvik/system/DexFile.java#141  
        XposedHelpers.findAndHookMethod(DexFile.class.getName(),   
                lpparam.classLoader, "loadDex",   
                String.class,   
                String.class, int.class,  
                new XC_MethodHook() {  
          
                @Override  
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {  
                      
                    if (!param.hasThrowable()) {  
                          
                        int falg = (Integer) param.args[2];  
                        // 加载的dex文件的路径  
                        String sourcePathName = (String) param.args[0];  
                        // dex被优化后的odex文件的存放路径  
                        String outputPathName = (String) param.args[1];  
                        logd("peikm", "sourcePathName:" + sourcePathName + " outputPathName:"   
                                + outputPathName + " falg:" + falg);
                        XposedBridge.log("sourcePathName:" + sourcePathName + " outputPathName:"   
                                        + outputPathName + " falg:" + falg);  
                          
                        // 获取dex文件被loadDex后返回的DexFile文件对象  
                        Object object = param.getResult();  
                        if (object instanceof DexFile) {  
                              
                            // 通过类反射获取DexFile类的私有成员mCookie的调用Field  
                            Field field = ((DexFile) object).getClass().getDeclaredField("mCookie");  
                            // 设置有权限  
                            field.setAccessible(true);  
                            // 获取到DexFile类的私有成员mCookie的值  
                            int cookie = field.getInt(object);  
                            // 恢复权限  
                            field.setAccessible(false);  
                            logd("peikm", "cookie:" + String.format("%x", cookie));
                              
                            // 创建线程对需要脱壳的apk进程进行内存dex的dump操作  
                            Thread thread = new Thread(new DexExtractor.dumpThread(cookie));  
                            // 启动线程  
                            thread.start();  
                        }  
                    }  
                }  
            });  
        }  
  
     public void logd(String tag, String msg){
    	 Log.d(tag, msg);
     }


}
