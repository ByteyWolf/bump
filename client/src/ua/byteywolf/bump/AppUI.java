package ua.byteywolf.bump;
import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.midlet.MIDlet;

import ua.byteywolf.bump.pages.LoginPage;

public class AppUI extends Canvas {

    public static final int TOPBAR_HEIGHT = 30;

    public static final Font boldFont = Font.getFont(Font.FACE_SYSTEM, Font.STYLE_BOLD, Font.SIZE_SMALL);
    public static final Font plainFont = Font.getFont(Font.FACE_SYSTEM, Font.STYLE_PLAIN, Font.SIZE_SMALL);

    public static ua.byteywolf.bump.pages.AppPage crtPage = LoginPage.INSTANCE;
    public static int accentBgARGB = 0x00FF00;
    public static int accentTxtARGB = 0x000000;
    public static int uiBgARGB = 0xFFFFFF;
    public static int uiTxtARGB = 0x000000;

    public static BUMPMessenger midlet;

    public static final BUMPProtocol messagingApi = new BUMPProtocol();

    public AppUI(BUMPMessenger creator) {
        setFullScreenMode(true);
        setTitle("BUMP Messenger");
        UIToolkit.initialize(getWidth(), getHeight(), accentBgARGB);
        midlet = creator;
    }

    protected void paint(Graphics g) {
        int width = getWidth();
        int height = getHeight();

        UIToolkit.blank(TOPBAR_HEIGHT + 5, g);

        g.setFont(boldFont);
        g.setColor(0, 0, 0);
        g.drawRect(0, 0, width, height);

        for (int i = 0; i < 3; i++) {
            setGraphicsColor(g, accentBgARGB, -(i * 25));
            g.fillRect(0, (TOPBAR_HEIGHT * i) / 4, width, TOPBAR_HEIGHT / 4);
        }

        setGraphicsColor(g, accentTxtARGB, 0);
        g.drawString(getTitle(), 5, 5, Graphics.LEFT | Graphics.TOP);

        g.setFont(plainFont);
        if (crtPage != null) {
            crtPage.paint(g, TOPBAR_HEIGHT, 0);
        } else {
            BUMPMessenger.showErrorAndExit("There is no page specified.");
        }
    }

    private void setGraphicsColor(Graphics g, int hexColor, int modifier) {
        int r = ((hexColor >> 16) & 0xFF) + modifier;
        int gChan = ((hexColor >> 8) & 0xFF) + modifier;
        int b = (hexColor & 0xFF) + modifier;

        if (r < 0)
            r = 0;
        else if (r > 255)
            r = 255;
        if (gChan < 0)
            gChan = 0;
        else if (gChan > 255)
            gChan = 255;
        if (b < 0)
            b = 0;
        else if (b > 255)
            b = 255;

        g.setColor(r, gChan, b);
    }

}