package chat.uki.app;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.PowerManager;
import android.provider.Settings;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.util.Base64;
import android.webkit.WebStorage;

import androidx.core.content.FileProvider;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import net.freehaven.tor.control.TorControlCommands;
import net.freehaven.tor.control.TorControlConnection;

import org.torproject.jni.TorService;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Anonymer Transport über Tor-Onion-Dienste.
 * Jedes Gerät bekommt eine neue .onion-Adresse. Der Schlüssel dazu geht nur an den JavaScript-Teil, der ihn
 * für einen offenen Kanal verschlüsselt (mit dem Login-Passwort) aufbewahrt, damit der Kanal einen Neustart übersteht.
 * Die Geräte verbinden sich über das Tor-Netz; keiner erfährt die IP-Adresse des anderen.
 * Rahmenformat auf der Leitung: [4 Byte Länge][1 Byte Ton ja/nein][Daten]. Die Daten sind bereits
 * Ende-zu-Ende-verschlüsselt (das macht der JavaScript-Teil).
 */
@CapacitorPlugin(name = "TorChat")
public class TorChatPlugin extends Plugin {

    private static final int VIRTUAL_PORT = 4747;
    private static final int MAX_FRAME = 1024 * 1024;
    private static final Pattern ONION = Pattern.compile("^[a-z2-7]{56}\\.onion$");

    private final ExecutorService io = Executors.newCachedThreadPool();

    private TorService torService;
    private ServiceConnection serviceConnection;
    private BroadcastReceiver statusReceiver;
    private volatile boolean torOn = false;
    private volatile String onionHost;
    private volatile String onionKey;
    private volatile String requestedKey;
    private volatile ServerSocket serverSocket;
    private static final int MAX_CONNS = 6;
    private final AtomicInteger nextConn = new AtomicInteger(1);
    private final Map<Integer, Conn> conns = new ConcurrentHashMap<>();
    private volatile int activeConn = 0;

    private static final class Conn {
        final int id;
        final Socket socket;
        final DataOutputStream out;
        Conn(int id, Socket s) throws IOException {
            this.id = id;
            this.socket = s;
            this.out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream(), 64 * 1024));
        }
    }
    private volatile boolean inForeground = true;
    private volatile PluginCall pendingStart;
    private volatile boolean progressRunning = false;

    // ------------------------------------------------------------------ Tor starten
    @PluginMethod
    public void start(PluginCall call) {
        String key = call.getString("key", null);
        if (key != null && !key.matches("^ED25519-V3:[A-Za-z0-9+/=]{40,120}$")) { call.reject("Ungültiger Schlüssel"); return; }
        if (onionHost != null && (key == null || key.equals(onionKey))) {
            JSObject r = new JSObject();
            r.put("address", onionHost);
            r.put("key", onionKey);
            call.resolve(r);
            return;
        }
        requestedKey = key;
        if (onionHost != null) {
            // Andere Adresse gewünscht (Wiederherstellung): alte Adresse abbauen
            removeOnion();
        }
        if (pendingStart != null) {
            pendingStart.reject("Tor startet bereits");
        }
        pendingStart = call;
        call.setKeepAlive(true);
        Context ctx = getContext();
        clearSharedFiles();
        KeepAliveService.start(ctx);

        if (statusReceiver == null) {
            statusReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    String status = intent.getStringExtra(TorService.EXTRA_STATUS);
                    if (TorService.STATUS_ON.equals(status) && !torOn) {
                        torOn = true;
                        io.execute(TorChatPlugin.this::createOnion);
                    }
                }
            };
            LocalBroadcastManager.getInstance(ctx).registerReceiver(statusReceiver, new IntentFilter(TorService.ACTION_STATUS));
        }

        if (serviceConnection == null) {
            serviceConnection = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    torService = ((TorService.LocalBinder) service).getService();
                    startProgressPolling();
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    torService = null;
                    torOn = false;
                }
            };
            ctx.bindService(new Intent(ctx, TorService.class), serviceConnection, Context.BIND_AUTO_CREATE);
        } else if (torOn) {
            io.execute(this::createOnion);
        }
    }

    private void startProgressPolling() {
        if (progressRunning) return;
        progressRunning = true;
        io.execute(() -> {
            Pattern p = Pattern.compile("PROGRESS=(\\d+)");
            Pattern s = Pattern.compile("SUMMARY=\"([^\"]*)\"");
            int last = -1;
            while (progressRunning && onionHost == null) {
                try {
                    TorService t = torService;
                    String phase = t != null ? t.getInfo("status/bootstrap-phase") : null;
                    if (phase != null) {
                        Matcher m = p.matcher(phase);
                        if (m.find()) {
                            int prog = Integer.parseInt(m.group(1));
                            if (prog != last) {
                                last = prog;
                                JSObject ev = new JSObject();
                                ev.put("progress", Math.min(prog, 99));
                                Matcher ms = s.matcher(phase);
                                ev.put("summary", ms.find() ? ms.group(1) : "");
                                notifyListeners("progress", ev);
                            }
                        }
                    }
                    Thread.sleep(700);
                } catch (InterruptedException e) {
                    break;
                } catch (Exception ignored) {
                }
            }
            progressRunning = false;
        });
    }

    private synchronized void createOnion() {
        PluginCall call = pendingStart;
        try {
            if (onionHost == null) {
                TorService t = torService;
                if (t == null) throw new IOException("Tor-Dienst nicht verbunden");
                TorControlConnection control = t.getTorControlConnection();
                if (control == null) throw new IOException("Tor-Steuerung nicht bereit");
                ServerSocket ss = new ServerSocket(0, 2, InetAddress.getByName("127.0.0.1"));
                serverSocket = ss;
                Map<Integer, String> ports = new HashMap<>();
                ports.put(VIRTUAL_PORT, "127.0.0.1:" + ss.getLocalPort());
                // NEW:ED25519-V3 = neue Adresse; DiscardPK = privater Schlüssel wird nicht zurückgegeben/gespeichert
                // Der Schlüssel wird von Tor nicht auf die Festplatte geschrieben (flüchtiger Dienst ohne "Detach").
                String want = requestedKey;
                Map<String, String> res = want != null
                        ? control.addOnion(want, ports, false, false)
                        : control.addOnion("NEW:ED25519-V3", ports, false, false);
                String addr = res.get(TorControlCommands.HS_ADDRESS);
                if (addr == null) throw new IOException("Keine Onion-Adresse erhalten");
                onionKey = want != null ? want : res.get(TorControlCommands.HS_PRIVKEY);
                onionHost = addr + ".onion";
                startAcceptLoop(ss);
            }
            JSObject ev = new JSObject();
            ev.put("progress", 100);
            ev.put("summary", "Bereit");
            notifyListeners("progress", ev);
            if (call != null) {
                JSObject r = new JSObject();
                r.put("address", onionHost);
                r.put("key", onionKey);
                call.resolve(r);
            }
        } catch (Exception e) {
            if (call != null) call.reject("Tor-Fehler: " + e.getMessage());
        } finally {
            if (call != null) {
                call.setKeepAlive(false);
                pendingStart = null;
            }
        }
    }

    private void startAcceptLoop(ServerSocket ss) {
        io.execute(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket s = ss.accept();
                    attach(s);
                } catch (IOException e) {
                    if (ss.isClosed()) break;
                }
            }
        });
    }

    @PluginMethod
    public void listen(PluginCall call) {
        call.resolve();
    }

    // ------------------------------------------------------------------ Verbinden
    @PluginMethod
    public void connect(PluginCall call) {
        String address = call.getString("address", "");
        if (address == null || !ONION.matcher(address).matches()) {
            call.reject("Ungültige Adresse");
            return;
        }
        io.execute(() -> {
            try {
                TorService t = torService;
                if (t == null || !torOn) throw new IOException("Tor ist nicht bereit");
                int socksPort = t.getSocksPort();
                if (socksPort <= 0) throw new IOException("Kein SOCKS-Port");
                Socket s = new Socket(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", socksPort)));
                s.connect(InetSocketAddress.createUnresolved(address, VIRTUAL_PORT), 120000);
                attach(s);
                call.resolve();
            } catch (Exception e) {
                call.reject("Verbindung fehlgeschlagen: " + e.getMessage());
            }
        });
    }

    private void attach(Socket s) throws IOException {
        if (conns.size() >= MAX_CONNS) {
            try { s.close(); } catch (IOException ignored) { }
            throw new IOException("Zu viele Verbindungen");
        }
        s.setTcpNoDelay(true);
        s.setKeepAlive(true);
        Conn c = new Conn(nextConn.getAndIncrement(), s);
        conns.put(c.id, c);
        JSObject ev = new JSObject();
        ev.put("state", "connected");
        ev.put("conn", c.id);
        notifyListeners("state", ev);
        io.execute(() -> readLoop(c));
        // Verbindungen, die sich nicht innerhalb von 60 Sekunden ausweisen, werden getrennt.
        io.execute(() -> {
            try { Thread.sleep(60000); } catch (InterruptedException ignored) { }
            if (activeConn != c.id && conns.containsKey(c.id)) closeConn(c.id, true);
        });
    }

    private void readLoop(Conn c) {
        try {
            DataInputStream in = new DataInputStream(new BufferedInputStream(c.socket.getInputStream(), 64 * 1024));
            while (true) {
                int len = in.readInt();
                if (len < 0 || len > MAX_FRAME) throw new IOException("Ungültiger Rahmen");
                boolean notify = in.readByte() == 1;
                byte[] buf = new byte[len];
                in.readFully(buf);
                JSObject ev = new JSObject();
                ev.put("data", Base64.encodeToString(buf, Base64.NO_WRAP));
                ev.put("conn", c.id);
                notifyListeners("data", ev);
                if (notify && !inForeground && activeConn == c.id) playSound();
            }
        } catch (IOException e) {
            // Verbindung beendet
        }
        closeConn(c.id, true);
    }

    private void closeConn(int id, boolean announce) {
        Conn c = conns.remove(id);
        if (c == null) return;
        if (activeConn == id) activeConn = 0;
        try { c.socket.close(); } catch (IOException ignored) { }
        if (announce) {
            JSObject ev = new JSObject();
            ev.put("state", "disconnected");
            ev.put("conn", id);
            notifyListeners("state", ev);
        }
    }

    private void closeAll() {
        for (Integer id : conns.keySet()) closeConn(id, false);
        activeConn = 0;
    }

    @PluginMethod
    public void promote(PluginCall call) {
        int id = call.getInt("conn", 0);
        if (!conns.containsKey(id)) { call.reject("Unbekannte Verbindung"); return; }
        activeConn = id;
        for (Integer other : conns.keySet()) if (other != id) closeConn(other, false);
        call.resolve();
    }

    @PluginMethod
    public void drop(PluginCall call) {
        closeConn(call.getInt("conn", 0), false);
        call.resolve();
    }

    // ------------------------------------------------------------------ Senden
    @PluginMethod
    public void send(PluginCall call) {
        String data = call.getString("data", "");
        boolean notify = Boolean.TRUE.equals(call.getBoolean("notify", false));
        int id = call.getInt("conn", 0);
        byte[] bytes;
        try {
            bytes = Base64.decode(data, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            call.reject("Ungültige Daten");
            return;
        }
        if (bytes.length > MAX_FRAME) {
            call.reject("Rahmen zu groß");
            return;
        }
        io.execute(() -> {
            Conn c = conns.get(id);
            try {
                if (c == null) throw new IOException("Nicht verbunden");
                synchronized (c) {
                    c.out.writeInt(bytes.length);
                    c.out.writeByte(notify ? 1 : 0);
                    c.out.write(bytes);
                    c.out.flush();
                }
                call.resolve();
            } catch (IOException e) {
                if (c != null) closeConn(c.id, true);
                call.reject("Senden fehlgeschlagen");
            }
        });
    }

    @PluginMethod
    public void closeConnection(PluginCall call) {
        closeAll();
        clearSharedFiles();
        call.resolve();
    }

    // ------------------------------------------------------------------ Beenden und Löschen
    @PluginMethod
    public void stop(PluginCall call) {
        shutdownTor();
        call.resolve();
    }

    private synchronized void removeOnion() {
        closeAll();
        try {
            TorService t = torService;
            String host = onionHost;
            if (t != null && host != null && t.getTorControlConnection() != null) {
                t.getTorControlConnection().delOnion(host.replace(".onion", ""));
            }
        } catch (Exception ignored) { }
        onionHost = null;
        onionKey = null;
        ServerSocket ss = serverSocket;
        serverSocket = null;
        if (ss != null) try { ss.close(); } catch (IOException ignored) { }
    }

    private void shutdownTor() {
        progressRunning = false;
        removeOnion();
        requestedKey = null;
        Context ctx = getContext();
        if (serviceConnection != null) {
            try { ctx.unbindService(serviceConnection); } catch (Exception ignored) { }
            serviceConnection = null;
        }
        try { ctx.stopService(new Intent(ctx, TorService.class)); } catch (Exception ignored) { }
        if (statusReceiver != null) {
            LocalBroadcastManager.getInstance(ctx).unregisterReceiver(statusReceiver);
            statusReceiver = null;
        }
        torService = null;
        torOn = false;
        KeepAliveService.stop(ctx);
        clearSharedFiles();
    }

    @PluginMethod
    public void wipe(PluginCall call) {
        shutdownTor();
        StateStore.clear(getContext());
        getActivity().runOnUiThread(() -> {
            try {
                getBridge().getWebView().clearCache(true);
                getBridge().getWebView().clearHistory();
                WebStorage.getInstance().deleteAllData();
            } catch (Exception ignored) { }
            deleteRecursive(getContext().getCacheDir(), false);
            call.resolve();
        });
    }

    // ------------------------------------------------------------------ Dokument öffnen
    @PluginMethod
    public void openFile(PluginCall call) {
        String data = call.getString("data", "");
        String name = call.getString("name", "Dokument");
        String mime = call.getString("mime", "application/octet-stream");
        io.execute(() -> {
            try {
                byte[] bytes = Base64.decode(data, Base64.DEFAULT);
                byte[] rnd = new byte[8];
                new SecureRandom().nextBytes(rnd);
                File dir = new File(new File(getContext().getCacheDir(), "shared"), Base64.encodeToString(rnd, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
                if (!dir.mkdirs() && !dir.isDirectory()) throw new IOException("Ordner");
                String safe = name.replaceAll("[^A-Za-z0-9._ -]", "_");
                if (safe.isEmpty()) safe = "Dokument";
                File f = new File(dir, safe);
                try (FileOutputStream fo = new FileOutputStream(f)) { fo.write(bytes); }
                Uri uri = FileProvider.getUriForFile(getContext(), getContext().getPackageName() + ".fileprovider", f);
                Intent i = new Intent(Intent.ACTION_VIEW);
                i.setDataAndType(uri, mime);
                i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
                getActivity().startActivity(Intent.createChooser(i, "Öffnen mit").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                call.resolve();
            } catch (Exception e) {
                call.reject("Keine App zum Öffnen gefunden");
            }
        });
    }

    private void clearSharedFiles() {
        deleteRecursive(new File(getContext().getCacheDir(), "shared"), true);
    }

    private static void deleteRecursive(File f, boolean self) {
        if (f == null || !f.exists()) return;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteRecursive(k, true);
        if (self) //noinspection ResultOfMethodCallIgnored
            f.delete();
    }

    // ------------------------------------------------------------------ Verschlüsselter Kanalzustand
    @PluginMethod
    public void saveState(PluginCall call) {
        String data = call.getString("data", "");
        Double exp = call.getDouble("expires");
        if (data == null || data.length() > 2_000_000 || exp == null) { call.reject("Ungültig"); return; }
        long expires = exp.longValue();
        io.execute(() -> {
            try {
                StateStore.save(getContext(), data, expires);
                call.resolve();
            } catch (Exception e) {
                call.reject("Speichern fehlgeschlagen");
            }
        });
    }

    @PluginMethod
    public void loadState(PluginCall call) {
        io.execute(() -> {
            JSObject r = new JSObject();
            String d = StateStore.load(getContext());
            if (d != null) r.put("data", d);
            call.resolve(r);
        });
    }

    @PluginMethod
    public void clearState(PluginCall call) {
        io.execute(() -> {
            StateStore.clear(getContext());
            call.resolve();
        });
    }

    // ------------------------------------------------------------------ Hintergrund
    // Bittet Android einmal, die App vom Akkusparen auszunehmen, damit der Kanal bei gesperrtem Handy hält.
    @PluginMethod
    public void keepAwake(PluginCall call) {
        try {
            Context ctx = getContext();
            PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            if (Build.VERSION.SDK_INT >= 23 && pm != null && !pm.isIgnoringBatteryOptimizations(ctx.getPackageName())) {
                Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                i.setData(Uri.parse("package:" + ctx.getPackageName()));
                getActivity().startActivity(i);
            }
        } catch (Exception ignored) { }
        call.resolve();
    }

    // ------------------------------------------------------------------ Ton
    private void playSound() {
        try {
            Uri u = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
            Ringtone r = RingtoneManager.getRingtone(getContext(), u);
            if (r != null) r.play();
        } catch (Exception ignored) { }
    }

    @Override
    protected void handleOnResume() {
        super.handleOnResume();
        inForeground = true;
    }

    @Override
    protected void handleOnPause() {
        super.handleOnPause();
        inForeground = false;
    }

    @Override
    protected void handleOnDestroy() {
        shutdownTor();
        super.handleOnDestroy();
    }
}
