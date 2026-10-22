"""python-for-android hook: declares the VpnService in AndroidManifest.xml (buildozer.spec: p4a.hook = p4a_hook.py)."""
import os

SERVICE = """
        <service android:name="org.netfree.netfree.NetFreeVpnService"
                 android:permission="android.permission.BIND_VPN_SERVICE"
                 android:exported="true">
            <intent-filter>
                <action android:name="android.net.VpnService"/>
            </intent-filter>
        </service>
"""


def _patch(toolchain):
    cands = []
    try:
        cands.append(os.path.join(toolchain._dist.dist_dir, "src", "main", "AndroidManifest.xml"))
    except Exception:
        pass
    cands += [os.path.join(os.getcwd(), "src", "main", "AndroidManifest.xml"), os.path.join(os.getcwd(), "AndroidManifest.xml")]
    for p in cands:
        if os.path.isfile(p):
            with open(p, encoding="utf8") as f:
                x = f.read()
            if "NetFreeVpnService" not in x:
                if "</application>" not in x:
                    continue
                x = x.replace("</application>", SERVICE + "    </application>", 1)
                with open(p, "w", encoding="utf8") as f:
                    f.write(x)
                print("[netfree hook] VpnService added to", p)
            return
    print("[netfree hook] WARNING: AndroidManifest.xml not found - VPN service NOT declared")


def after_apk_build(toolchain): _patch(toolchain)
def before_apk_assemble(toolchain): _patch(toolchain)
