package chat.uki.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import androidx.core.app.NotificationCompat;
import androidx.core.app.ServiceCompat;

/**
 * Hält die App am Leben, solange Tor läuft, damit Nachrichten auch im Hintergrund ankommen.
 * Android verlangt dafür eine dauerhafte Benachrichtigung. Sie enthält keinerlei Inhalt,
 * keinen Namen und keine Nachricht, nur "UKI CHAT ist aktiv".
 */
public class KeepAliveService extends Service {

    private static final String CHANNEL = "uki_keepalive";
    private static final int ID = 4747;
    private PowerManager.WakeLock wakeLock;

    public static void start(Context ctx) {
        try {
            Intent i = new Intent(ctx, KeepAliveService.class);
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i);
            else ctx.startService(i);
        } catch (Exception ignored) {
            // Ohne Hintergrunddienst funktioniert der Chat trotzdem, solange die App offen ist.
        }
    }

    public static void stop(Context ctx) {
        try { ctx.stopService(new Intent(ctx, KeepAliveService.class)); } catch (Exception ignored) { }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null && nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "Aktiv", NotificationManager.IMPORTANCE_MIN);
            ch.setShowBadge(false);
            ch.setSound(null, null);
            ch.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);
        Notification n = new NotificationCompat.Builder(this, CHANNEL)
                .setContentTitle("UKI CHAT ist aktiv")
                .setSmallIcon(R.mipmap.ic_launcher)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                .setOngoing(true)
                .setSilent(true)
                .setContentIntent(pi)
                .build();
        try {
            int type = Build.VERSION.SDK_INT >= 34 ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0;
            ServiceCompat.startForeground(this, ID, n, type);
        } catch (Exception e) {
            stopSelf();
        }
        // Hält den Prozessor wach, damit Tor und der Kanal auch bei gesperrtem Bildschirm weiterlaufen.
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (pm != null && wakeLock == null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "uki:channel");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire(13L * 60 * 60 * 1000); // höchstens 13 Stunden
            }
        } catch (Exception ignored) { }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        try { if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); } catch (Exception ignored) { }
        wakeLock = null;
        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        // App wurde weggewischt: alles beenden, nichts bleibt zurück.
        stopSelf();
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
