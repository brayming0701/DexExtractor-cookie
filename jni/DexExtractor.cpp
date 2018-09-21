#include <jni.h>
#include <stdio.h>
#include <unistd.h>
//#include <string>
#include <android/log.h>
#include "Object.h"

//using std::string;
#define  LOG_TAG "peikm"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)

char* getExternalStorageDirectory(JNIEnv* env);
void printinfo(const char* tag, const char* fmt, ...);


char* jstringTostring(JNIEnv* env, jstring str)
{
    char* rtn = NULL;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("utf-8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray)env->CallObjectMethod(str, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0)
    {
        rtn = (char*)malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);

    return rtn;
}

// 通过jni函数反射调用java方法获取到设备的scard卡的文件路径
char* getExternalStorageDirectory(JNIEnv* env)
{
    jclass Environment = env->FindClass("android/os/Environment");
    if (Environment != NULL)
    {
        //Messageprint::printinfo("util", "Environment class have found");
        jmethodID getExternalStorageDirectoryID = env->GetStaticMethodID(Environment,
        							"getExternalStorageDirectory", "()Ljava/io/File;");
        if (getExternalStorageDirectoryID != NULL)
        {
            jobject fileobject = env->CallStaticObjectMethod(Environment, getExternalStorageDirectoryID);
            jclass Fileclass = env->FindClass("java/io/File");
            jmethodID getAbsolutePathId = env->GetMethodID(Fileclass, "getAbsolutePath", "()Ljava/lang/String;");
            jstring jstringPath = (jstring)env->CallObjectMethod(fileobject, getAbsolutePathId);
            char* StorageDirectoryPath = jstringTostring(env, jstringPath);
            return StorageDirectoryPath;
        }
    }

    return NULL;
}


// 使用了stl的库函数
#ifdef __cplusplus
extern "C" {
#endif
int nums = 0;
// 调用native层实现的jni方法dumpdex
JNIEXPORT void JNICALL Java_com_peikm_dexextractor_DexExtractor_dumpdex(JNIEnv *env, jobject instance, jint cookie) {

	DexOrJar* pDexOrJar = (DexOrJar*)cookie;
	DvmDex* pDvmDex;
	//打印dex文件的内存加载路径
	LOGD("jni %s", pDexOrJar->fileName);

	// 判断当前mCookie值是否是dex文件的
	if (pDexOrJar->isDex)
	{
		// 得到内存加载的odex文件的信息结构体
		pDvmDex = pDexOrJar->pRawDexFile->pDvmDex;
	}
	else
	{
		pDvmDex = pDexOrJar->pJarFile->pDvmDex;
	}

	// 获取到描述内存加载的odex文件信息的结构体DexFile
	DexFile* dexFile = pDvmDex->pDexFile;
	// 得到内存加载的odex文件的基地址（起始地址）
	MemMapping mapping = pDvmDex->memMap;
	LOGD("jni MemMapping:addr:%x length:%x baseAddr:%x baseLength:%x",
			 mapping.addr, mapping.length, mapping.baseAddr, mapping.baseLength);

	// 通过jni函数反射调用java方法获取到设备的scard卡的文件路径
	char* path = getExternalStorageDirectory(env);

	char szBufferDexPath[128];
	memset(szBufferDexPath, 0, sizeof(szBufferDexPath));
	memcpy(szBufferDexPath, path, strlen(path));
	// 拼接字符串得到dump的dex文件的路径
	char  dexFileName[20] = {0};
	sprintf(dexFileName,"/tmp/classes%d.dex",nums);
	strcat(szBufferDexPath, dexFileName);
	LOGD("dump dex path: %s", szBufferDexPath);

	// F_OK = 0
	if (!access(szBufferDexPath,  F_OK))
	{
		// 删除已经存在的文件
		remove(szBufferDexPath);
	}

	// 创建新文件保存dump的dex文件
	FILE* file = fopen(szBufferDexPath, "wb+");

	// 保存三倍dex文件长度(比较暴力，可以参考dexhunter的实现代码进行优化)
	fwrite(mapping.addr,mapping.length*3,1,file);

	// 关闭文件
	fclose(file);
	memset(dexFileName, 0, 20);
	memset(szBufferDexPath, 0, 128);

}

#ifdef __cplusplus
}
#endif

