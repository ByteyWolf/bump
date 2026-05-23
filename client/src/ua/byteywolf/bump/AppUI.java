package ua.byteywolf.bump;
import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;

import ua.byteywolf.bump.pages.LoginPage;

public class AppUI extends Canvas implements Runnable {

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

    private volatile static int heldGameAction = 0;
    private volatile static long heldStartTime = 0;

    public static AppUI instance;

    public AppUI(BUMPMessenger creator) {
        instance = this;
        setFullScreenMode(true);
        setTitle("Lupin Messenger");
        UIToolkit.initialize(getWidth(), getHeight(), accentBgARGB, crtPage, creator);
        midlet = creator;
        new Thread(this).start();
    }

    protected void paint(Graphics g) {
        int width = getWidth();
        int height = getHeight();

        g.setColor(0, 0, 0);
        g.fillRect(0, 0, width, height);

        UIToolkit.blank(TOPBAR_HEIGHT + 5, g, 0);

        g.setFont(plainFont);
        if (crtPage != null) {
            crtPage.paint(g, TOPBAR_HEIGHT, 0);
        } else {
            BUMPMessenger.showErrorAndExit("There is no page specified.");
        }

        UIToolkit.finish();

        g.setFont(boldFont);

        int quartHeight = TOPBAR_HEIGHT / 4;
        for (int i = 0; i <= 3; i++) {
            setGraphicsColor(g, accentBgARGB, -(i * 25));
            g.fillRect(0, quartHeight * i, width, quartHeight);
        }

        int fontHeight = g.getFont().getHeight();
        setGraphicsColor(g, accentTxtARGB, 0);
        g.drawString(getTitle(), 5, (TOPBAR_HEIGHT - fontHeight) / 2, Graphics.LEFT | Graphics.TOP);
    }

    public void run() {
        while (true) {
            try {Thread.sleep(100);} catch (InterruptedException e) {}
            while (heldGameAction >= 0 && heldStartTime != 0 && System.currentTimeMillis() - heldStartTime > 400) {
                keyPressedBehavior(getKeyCode(heldGameAction));
                try {Thread.sleep(80);} catch (InterruptedException e) {}
                if (heldGameAction == -1) break;
            }
        }
    }

    protected void keyPressed(int keyCode) {
        keyPressedBehavior(keyCode);
        int gameAction = getGameAction(keyCode);
        if (gameAction == LEFT || gameAction == RIGHT || gameAction == UP || gameAction == DOWN) {
            heldGameAction = gameAction;
            heldStartTime = System.currentTimeMillis();
        }
    }

    private void keyPressedBehavior(int keyCode) {
        int gameAction = getGameAction(keyCode);
        UIToolkit.keyPressed(gameAction);
        repaint();
    }

    protected void keyReleased(int keyCode) {
        if (heldGameAction == getGameAction(keyCode)) heldGameAction = -1;
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