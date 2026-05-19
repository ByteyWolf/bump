package ua.byteywolf.bump.pages;

import javax.microedition.lcdui.Graphics;
import ua.byteywolf.bump.*;

public class LoginPage implements AppPage {
    public static final LoginPage INSTANCE = new LoginPage();

    public void paint(Graphics g, int topOffset, int bottomOffset) {
        UIToolkit.TextLabel("label test");
        UIToolkit.UIEntryBox("testing entry box", false);
    }
}
