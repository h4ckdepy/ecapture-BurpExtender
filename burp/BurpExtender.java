

package burp;
import com.google.gson.JsonParser;
import sun.net.util.IPAddressUtil;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender {

    private final static String NAME = "ecapture-BurpLoader";
    private PrintWriter stdout;
    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;

    //注册监听器
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(NAME);
        stdout.println("@Name:ecapture-BurpLoader");
        stdout.println("@Author:depy@Meituan");
        stdout.println("@Version:0.0.1");
        stdout.println("@Introduce:Used to load the plaintext request message captured by the <Ecapture> into the <Repeater> module of the Bursuite");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }


}