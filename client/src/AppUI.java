import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;

public class AppUI extends Canvas {

    public static final int PAGE_LOGIN = 0;
    public static final int TOPBAR_HEIGHT = 20;

    public static final Font boldFont = Font.getFont(Font.FACE_SYSTEM, Font.STYLE_BOLD, Font.SIZE_MEDIUM);
    public static final Font plainFont = Font.getFont(Font.FACE_SYSTEM, Font.STYLE_PLAIN, Font.SIZE_SMALL);

    public static int crtPage = PAGE_LOGIN;
    public static int accentBgARGB = 0x00FF00;
    public static int accentTxtARGB = 0x000000;
    public static int uiBgARGB = 0xFFFFFF;
    public static int uiTxtARGB = 0x000000;


    public AppUI() {
        setFullScreenMode(true);
        setTitle("BUMP Messenger");
    }

    protected void paint(Graphics g) {
        int width = getWidth();
        int height = getHeight();
        
        g.setFont(boldFont);
        for (int i = 0; i<3; i++) {
            g.setColor((accentBgARGB >> 16) & (0xFF-i), (accentBgARGB >> 8) & (0xFF-i), accentBgARGB & (0xFF-i));
            g.fillRect(0, TOPBAR_HEIGHT * i / 4, width, TOPBAR_HEIGHT / 4);
        }
        g.drawString(getTitle(), 5, 5, Graphics.LEFT | Graphics.TOP);
        g.setFont(plainFont);
        
        // here we would hand over painting to the individual pages
    }
}