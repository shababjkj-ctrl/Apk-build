[app]
title = SHAHIL FF Monitor
package.name = shahil_ffmonitor
package.domain = com.shahil.ffmonitor

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
source.include_patterns = udpcapture_1.py

version = 1.0.0

requirements = python3,kivy==2.3.2,pycryptodome,requests==2.25.1,urllib3==1.26.20,chardet==4.0.0

orientation = portrait

# Android permissions
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,FOREGROUND_SERVICE

android.minapi = 24
android.api = 33
android.sdk = 33
android.ndk = 25c
android.ndk_api = 24

android.archs = arm64-v8a, armeabi-v7a

android.allow_backup = True
android.accept_sdk_license = True
p4a.branch = develop
p4a.commit = d2ee8c5


[buildozer]
log_level = 2
warn_on_root = 1
