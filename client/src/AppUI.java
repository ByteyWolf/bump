import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;

public class AppUI extends Canvas {

    public static final int PAGE_LOGIN = 0;
    public static final int TOPBAR_HEIGHT = 40;

    public static final Font boldFont = Font.getFont(Font.FACE_SYSTEM, Font.STYLE_BOLD, Font.SIZE_MEDIUM);
    public static final Font plainFont = Font.getFont(Font.FACE_SYSTEM, Font.STYLE_PLAIN, Font.SIZE_SMALL);

    public static int crtPage = PAGE_LOGIN;
    public static int accentBgARGB = 0x00FF00;
    public static int accentTxtARGB = 0x000000;
    public static int uiBgARGB = 0xFFFFFF;
    public static int uiTxtARGB = 0x000000;

    public static final BUMPProtocol messagingApi = new BUMPProtocol();

    public AppUI() {
        setFullScreenMode(true);
        setTitle("BUMP Messenger");
    }

    protected void paint(Graphics g) {
        int width = getWidth();
        int height = getHeight();

        g.setFont(boldFont);

        for (int i = 0; i < 3; i++) {
            setGraphicsColor(g, accentBgARGB, -(i * 25));
            g.fillRect(0, (TOPBAR_HEIGHT * i) / 4, width, TOPBAR_HEIGHT / 4);
        }

        setGraphicsColor(g, accentTxtARGB, 0);
        g.drawString(getTitle(), 5, 5, Graphics.LEFT | Graphics.TOP);

        g.setFont(plainFont);
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
