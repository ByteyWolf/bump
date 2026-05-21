package ua.byteywolf.bump.pages;

import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.lcdui.TextField;

import ua.byteywolf.bump.*;

public class LoginPage implements AppPage {
    public static final LoginPage INSTANCE = new LoginPage();
    public static final int USERNAME_FIELD = 0;
    public static final int PASSWORD_FIELD = 1;
    public static final int LOGIN_BTN = 2;

    public static String username = "";
    public static String passwordPlaintext = ""; // why the hell do we need to encrypt this if its in ram only
    public static String passwordMasked = "";

    public void paint(Graphics g, int topOffset, int bottomOffset) {
        g.setFont(Font.getFont(Font.FACE_SYSTEM, Font.STYLE_BOLD | Font.STYLE_ITALIC, Font.SIZE_MEDIUM));
        UIToolkit.TextLabel("Welcome!");
        g.setFont(Font.getFont(Font.FACE_SYSTEM, Font.STYLE_PLAIN, Font.SIZE_SMALL));
        UIToolkit.TextLabel("Please sign into your proxy.");
        UIToolkit.Gap(10);
        UIToolkit.EntryBox("Username:", username, "bitesyou@wolf.com");
        UIToolkit.EntryBox("Password:", passwordMasked, "hunter2");
        UIToolkit.TextButton("this is a button");
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
                throw new RuntimeException("*bites you*");
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
            case LOGIN_BTN:
                throw new RuntimeException("*bites you*");
        }
    }
}
