package io.github.eirv.simpleioredirect;

import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.widget.TextView;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MainActivity extends Activity {
    private static final String TARGET_PATH = "/just/for/fun";

    static {
        System.loadLibrary("io-redirect");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        File redirection = new File(getDataDir(), "redirection.txt");
        try {
            Files.write(redirection.toPath(), "This is redirection.txt".getBytes());
        } catch (IOException ignored) {
        }

        ActionBar actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setSubtitle(TARGET_PATH);
        }

        if (!redirect(TARGET_PATH, redirection.getPath())) {
            new AlertDialog.Builder(this)
                    .setTitle("Error")
                    .setMessage("This example cannot be run on your device and requires at least kernel version 5.10")
                    .setPositiveButton(android.R.string.ok, null)
                    .create()
                    .show();
        }

        TextView textView = new TextView(this);
        textView.setText(readFile(TARGET_PATH));
        setContentView(textView);
    }

    private static String readFile(String path) {
        try {
            return new String(Files.readAllBytes(Paths.get(path)));
        } catch (IOException e) {
            return e.toString();
        }
    }

    public static native boolean redirect(String target, String redirection);
}
