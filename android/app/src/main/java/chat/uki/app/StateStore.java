package chat.uki.app;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

/**
 * Bewahrt den Zustand EINES offenen Kanals auf, damit er 12 Stunden hält, auch wenn Android die App beendet.
 * Der Inhalt ist bereits im JavaScript-Teil verschlüsselt (Schlüssel aus dem Login-Passwort, nie gespeichert).
 * Hier steht nur: [8 Byte Ablaufzeit][verschlüsselte Daten]. Nachrichten werden nie gespeichert.
 * Zur Ablaufzeit löscht ein Android-Wecker die Datei, auch wenn die App nicht läuft.
 */
public final class StateStore {
    private static final String NAME = "uki.state";

    private StateStore() { }

    private static File file(Context ctx) { return new File(ctx.getNoBackupFilesDir(), NAME); }

    public static synchronized void save(Context ctx, String data, long expires) throws Exception {
        File f = file(ctx);
        File tmp = new File(f.getParentFile(), NAME + ".tmp");
        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(tmp))) {
            out.writeLong(expires);
            out.write(data.getBytes(StandardCharsets.US_ASCII));
            out.flush();
        }
        if (!tmp.renameTo(f)) { overwriteAndDelete(tmp); throw new Exception("rename"); }
        schedule(ctx, expires);
    }

    public static synchronized String load(Context ctx) {
        File f = file(ctx);
        if (!f.exists()) return null;
        try (DataInputStream in = new DataInputStream(new FileInputStream(f))) {
            long expires = in.readLong();
            if (expires <= System.currentTimeMillis()) { in.close(); clear(ctx); return null; }
            byte[] rest = new byte[(int) Math.max(0, f.length() - 8)];
            in.readFully(rest);
            return new String(rest, StandardCharsets.US_ASCII);
        } catch (Exception e) {
            clear(ctx);
            return null;
        }
    }

    public static synchronized void clear(Context ctx) {
        overwriteAndDelete(file(ctx));
        overwriteAndDelete(new File(ctx.getNoBackupFilesDir(), NAME + ".tmp"));
        try {
            AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
            if (am != null) am.cancel(pending(ctx));
        } catch (Exception ignored) { }
    }

    /** Beim Start der App: abgelaufenen Zustand sofort löschen. */
    public static void purgeExpired(Context ctx) { load(ctx); }

    private static void overwriteAndDelete(File f) {
        if (f == null || !f.exists()) return;
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            byte[] zero = new byte[4096];
            long len = raf.length();
            for (long o = 0; o < len; o += zero.length) raf.write(zero, 0, (int) Math.min(zero.length, len - o));
        } catch (Exception ignored) { }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private static PendingIntent pending(Context ctx) {
        Intent i = new Intent(ctx, WipeReceiver.class);
        return PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private static void schedule(Context ctx, long expires) {
        try {
            AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
            // Ungenauer Wecker (keine Sondererlaubnis nötig). Android kann ihn etwas verzögern;
            // die App selbst prüft die Ablaufzeit zusätzlich bei jedem Start.
            if (am != null) am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, expires + 1000, pending(ctx));
        } catch (Exception ignored) { }
    }

    /** Wird vom Wecker aufgerufen. */
    public static class WipeReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            purgeExpired(context);
        }
    }
}
