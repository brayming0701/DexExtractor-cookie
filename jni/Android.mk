LOCAL_PATH := $(call my-dir)  
  
include $(CLEAR_VARS)  
  
LOCAL_MODULE    := native  
LOCAL_SRC_FILES := DexExtractor.cpp 
  
# 支持log日志打印需要加载链接的库      
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog      
  
include $(BUILD_SHARED_LIBRARY)  