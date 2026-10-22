package org.netfree.netfree;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * Real Android VPN (the "key" icon). It only creates the TUN interface and hands the raw fd to Python
 * (tun2socks.py), which turns the packets into connections for the NetFree engine.
 * The app itself is excluded from the VPN, so the engine's own upstream sockets never loop back.
 */
public class NetFreeVpnService extends VpnService {
    public static volatile int fd = -1;
    public static volatile boolean up = false;
    public static volatile String error = "";
    public static volatile String bypass = "";   // comma separated package names that skip the VPN
    private static NetFreeVpnService inst;
    private ParcelFileDescriptor pfd;

    // everything except private / loopback / multicast ranges, so LAN, hotspot and casting keep working
    private static final String[] ROUTES = {"1.0.0.0/8","2.0.0.0/7","4.0.0.0/6","8.0.0.0/7","11.0.0.0/8","12.0.0.0/6","16.0.0.0/4","32.0.0.0/3","64.0.0.0/3","96.0.0.0/6","100.0.0.0/10","100.128.0.0/9","101.0.0.0/8","102.0.0.0/7","104.0.0.0/5","112.0.0.0/5","120.0.0.0/6","124.0.0.0/7","126.0.0.0/8","128.0.0.0/3","160.0.0.0/5","168.0.0.0/8","169.0.0.0/9","169.128.0.0/10","169.192.0.0/11","169.224.0.0/12","169.240.0.0/13","169.248.0.0/14","169.252.0.0/15","169.255.0.0/16","170.0.0.0/7","172.0.0.0/12","172.32.0.0/11","172.64.0.0/10","172.128.0.0/9","173.0.0.0/8","174.0.0.0/7","176.0.0.0/4","192.0.0.0/9","192.128.0.0/11","192.160.0.0/13","192.169.0.0/16","192.170.0.0/15","192.172.0.0/14","192.176.0.0/12","192.192.0.0/10","193.0.0.0/8","194.0.0.0/7","196.0.0.0/6","200.0.0.0/5","208.0.0.0/4"};

    public static boolean needsConsent(Activity a) { return VpnService.prepare(a) != null; }

    public static void askConsent(Activity a, int code) {
        Intent i = VpnService.prepare(a);
        if (i != null) a.startActivityForResult(i, code);
    }

    public static void start(Activity a) { a.startService(new Intent(a, NetFreeVpnService.class)); }

    public static void stop() {
        NetFreeVpnService s = inst;
        if (s != null) s.teardown(); else { up = false; fd = -1; }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        inst = this;
        if (pfd == null) {
            try {
                Builder b = new Builder();
                b.setSession("NetFree");
                b.setMtu(1500);
                b.addAddress("10.8.0.2", 24);
                for (String r : ROUTES) {
                    String[] p = r.split("/");
                    b.addRoute(p[0], Integer.parseInt(p[1]));
                }
                b.addDnsServer("1.1.1.1");
                b.addDnsServer("8.8.8.8");
                try { b.addAddress("fd00:8::2", 64); b.addRoute("::", 0); } catch (Exception e) { }   // IPv6 black-hole (no leaks)
                try { b.addDisallowedApplication(getPackageName()); } catch (Exception e) { }
                if (bypass != null && bypass.length() > 0) {
                    for (String pkg : bypass.split(",")) {
                        pkg = pkg.trim();
                        if (pkg.length() > 0) { try { b.addDisallowedApplication(pkg); } catch (Exception e) { } }
                    }
                }
                if (Build.VERSION.SDK_INT >= 29) { try { b.setMetered(false); } catch (Exception e) { } }
                try {
                    Intent li = getPackageManager().getLaunchIntentForPackage(getPackageName());
                    if (li != null) b.setConfigureIntent(PendingIntent.getActivity(this, 0, li, PendingIntent.FLAG_IMMUTABLE));
                } catch (Exception e) { }
                pfd = b.establish();
                if (pfd == null) { error = "establish() returned null (permission revoked?)"; up = false; fd = -1; stopSelf(); return START_NOT_STICKY; }
                fd = pfd.getFd();
                error = "";
                up = true;
            } catch (Exception e) {
                error = String.valueOf(e);
                up = false; fd = -1;
                stopSelf();
            }
        }
        return START_NOT_STICKY;   // never auto-restart: without Python the tunnel would be a black hole
    }

    private void teardown() {
        up = false; fd = -1;
        try { if (pfd != null) pfd.close(); } catch (Exception e) { }
        pfd = null;
        stopSelf();
    }

    @Override public void onRevoke() { teardown(); super.onRevoke(); }
    @Override public void onDestroy() { up = false; fd = -1; try { if (pfd != null) pfd.close(); } catch (Exception e) { } pfd = null; inst = null; super.onDestroy(); }
}
