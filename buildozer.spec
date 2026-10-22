[app]
p4a.branch = v2024.01.21
android.ndk = 25b
title = NetFree
package.name = netfree
package.domain = org.netfree
source.dir = .
source.include_exts = py,png,jpg,ttf,java
source.include_patterns = fonts/*,java/*
version = 2.1
# openssl + certifi: needed for TLS; arabic-reshaper + python-bidi(0.4.2 = pure python): Persian text
# tun2socks.py (stdlib only) ships alongside main.py and is picked up by source.include_exts=py automatically.
requirements = python3,kivy==2.3.0,openssl,certifi,arabic-reshaper==3.0.0,python-bidi==0.4.2,six,pyjnius,android
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a
android.accept_sdk_license = True
# Real system VPN (NetFreeVpnService.java) for the "key icon" connection: its sources are compiled into
# the app, and p4a_hook.py adds the <service> + VpnService intent-filter to AndroidManifest.xml that p4a's
# own template does not generate for you.
android.add_src = java
p4a.hook = p4a_hook.py

[buildozer]
log_level = 2
warn_on_root = 1
