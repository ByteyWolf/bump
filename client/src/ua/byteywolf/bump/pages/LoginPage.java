package ua.byteywolf.bump.pages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;

import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.lcdui.TextField;
import javax.microedition.rms.RecordStore;

import ua.byteywolf.bump.*;

public class LoginPage implements AppPage {
    public static final LoginPage INSTANCE = new LoginPage();
    public static final int USERNAME_FIELD = 0;
    public static final int PASSWORD_FIELD = 1;
    public static final int LOGIN_BTN = 2;
    public static final int REMEMBER_CHK = 4;
    public static final int SERVER_FIELD = 3;

    public static final String STORE_NAME = "BUMPMsgAuth";

    public static String username = "";
    public static String passwordPlaintext = ""; // why the hell do we need to encrypt this if its in ram only
    public static String passwordMasked = "";
    public static String serverName = "";
    public static boolean rememberUser = true;
    public static boolean initialized = false;

    public void initialize() {
        RecordStore rs = null;
        try {
            rs = RecordStore.openRecordStore(STORE_NAME, false);
            if (rs.getNumRecords() > 0) {
                byte[] data = rs.getRecord(1);
                
                ByteArrayInputStream bais = new ByteArrayInputStream(data);
                DataInputStream dis = new DataInputStream(bais);
                
                serverName = dis.readUTF();
                rememberUser = dis.readBoolean();
                if (rememberUser) {
                    username = dis.readUTF();
                    passwordPlaintext = dis.readUTF();

                    char[] chars = new char[passwordPlaintext.length()];
                    for (int i = 0; i < chars.length; i++) {
                        chars[i] = '*';
                    }
                    passwordMasked = new String(chars);
                }
                
                dis.close();
                bais.close();
            }
        } catch (Exception e) {
            
        } finally {
            if (rs != null) {
                try { rs.closeRecordStore(); } catch (Exception e) {}
            }
        }
        initialized = true;
    }

    public void paint(Graphics g, int topOffset, int bottomOffset) {
        if (!initialized) initialize();
        g.setFont(Font.getFont(Font.FACE_SYSTEM, Font.STYLE_BOLD | Font.STYLE_ITALIC, Font.SIZE_MEDIUM));
        UIToolkit.TextLabel("Welcome!");
        g.setFont(Font.getFont(Font.FACE_SYSTEM, Font.STYLE_PLAIN, Font.SIZE_SMALL));
        UIToolkit.TextLabel("Please sign into your proxy.");
        UIToolkit.Gap(10);
        UIToolkit.EntryBox("Username:", username, "bitesyou@wolf.com");
        UIToolkit.EntryBox("Password:", passwordMasked, "hunter2");
        UIToolkit.TextButton("Log In");
        UIToolkit.Separator("Additional options");
        UIToolkit.EntryBox("Server:", serverName, "bump.byteywolf.com");
        UIToolkit.TextLabel("Include the port in the address. Do not specify the default address, it will not work! You must specify the address of your self-hosted instance.");
        UIToolkit.Gap(10);
        UIToolkit.Checkbox("Remember me", rememberUser);
    }

    public void elementSelect(int elementId) {
        switch (elementId) {
            case USERNAME_FIELD:
                UIToolkit.promptText("Enter your username", username, 256);
                break;
            case PASSWORD_FIELD:
                UIToolkit.promptText("Enter your password", passwordPlaintext, 256, TextField.PASSWORD);
                break;
            case LOGIN_BTN:
                save();
                throw new RuntimeException("*bites you*");
            case REMEMBER_CHK:
                rememberUser = !rememberUser;
                save();
                break;
            case SERVER_FIELD:
                UIToolkit.promptText("Enter proxy address", serverName, 256);
                break;
        }
    }

    public void textSaved(int elementId, String text) {
        switch (elementId) {
            case USERNAME_FIELD:
                username = text;
                break;
            case PASSWORD_FIELD:
                passwordPlaintext = text;
                
                char[] chars = new char[text.length()];
                for (int i = 0; i < chars.length; i++) {
                    chars[i] = '*';
                }
                passwordMasked = new String(chars);
                break;
            case SERVER_FIELD:
                serverName = text;
                break;
        }
        save();
    }

    public static void save() {
        RecordStore rs = null;
        try {
            try { RecordStore.deleteRecordStore(STORE_NAME); } catch (Exception e) {}
            
            rs = RecordStore.openRecordStore(STORE_NAME, true);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            
            dos.writeUTF(serverName);
            dos.writeBoolean(rememberUser);
            if (rememberUser) {
                dos.writeUTF(username);
                dos.writeUTF(passwordPlaintext);
            }
            dos.flush();
            
            byte[] data = baos.toByteArray();
            rs.addRecord(data, 0, data.length);
            
            dos.close();
            baos.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (rs != null) {
                try { rs.closeRecordStore(); } catch (Exception e) {}
            }
        }
    }
}
