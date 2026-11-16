package chat.uki.app;

import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(TorChatPlugin.class);
        super.onCreate(savedInstanceState);
        // Keine Bildschirmfotos, keine Bildschirmaufnahmen, kein Vorschaubild in der App-Übersicht.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    }
}
