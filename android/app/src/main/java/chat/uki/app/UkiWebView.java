package chat.uki.app;

import android.content.Context;
import android.text.InputType;
import android.util.AttributeSet;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;

import com.getcapacitor.CapacitorWebView;

/**
 * WebView, die der Tastatur verbietet, getippte Wörter zu lernen oder zu speichern
 * (wie der Inkognito-Modus der Tastatur). Gilt für alle Eingabefelder der App.
 */
public class UkiWebView extends CapacitorWebView {
    public UkiWebView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    @Override
    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        InputConnection ic = super.onCreateInputConnection(outAttrs);
        outAttrs.imeOptions |= EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
        if ((outAttrs.inputType & InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT) {
            outAttrs.inputType |= InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;
        }
        return ic;
    }
}
