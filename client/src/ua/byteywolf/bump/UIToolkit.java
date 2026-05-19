package ua.byteywolf.bump;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;

public class UIToolkit {
    // An assortment of ready-to-use UI elements for BUMP.
    // Useful for creating forms.

    public static final int X_PADDING = 5;
    public static final int BTN_DEPTH = 3;

    private static int offset = 0;
    private static Graphics g;
    public static int screenWidth = 0;
    public static int screenHeight = 0;

    private static int accentR = 0;
    private static int accentG = 0;
    private static int accentB = 0;

    public static void initialize(int newWidth, int newHeight, int newAccentColorRgba) {
        screenWidth = newWidth;
        screenHeight = newHeight;

        accentR = ((newAccentColorRgba >> 16) & 0xFF);
        accentG = ((newAccentColorRgba >> 8) & 0xFF);
        accentB = (newAccentColorRgba & 0xFF);
    }

    public static void blank(int newOffset, Graphics newGraphics) {
        offset = newOffset;
        g = newGraphics;
    }

    public static int TextLabel(String text) {
        g.setColor(255, 255, 255);
        return drawWrappedText(g, text, X_PADDING, offset, screenWidth - (X_PADDING * 2));
    }

    public static int UIEntryBox(String textEntered, boolean selected) {
        int boxHeight = g.getFont().getHeight() * 3 / 2;

        g.setColor(40, 40, 40);
        if (selected) g.setColor(accentR, accentG, accentB);
        g.fillRect(X_PADDING, offset, screenWidth - (X_PADDING * 2), boxHeight);
        g.setColor(20, 20, 20);
        if (selected) g.setColor(50, 50, 50);
        g.fillRect(X_PADDING + 1, offset + 1, screenWidth - (X_PADDING * 2) - 2, boxHeight - 2);

        g.setColor(255, 255, 255);
        g.drawString(textEntered, X_PADDING * 2, offset + (boxHeight / 2), Graphics.VCENTER | Graphics.LEFT);

        return boxHeight * 6 / 5;
    }

    public static int TextButton(String text, boolean selected) {
        int boxHeight = g.getFont().getHeight() * 3 / 2 + (BTN_DEPTH * 2);
        int width = X_PADDING * 2 + g.getFont().stringWidth(text) + (X_PADDING * 2);

        for (int i = 0; i < BTN_DEPTH; i++) {
            g.setColor(255 - (i*5), 255 - (i*5), 255 - (i*5));
            if (selected) g.setColor(accentR - (i*5), accentG - (i*5), accentB - (i*5));
            g.fillRect(X_PADDING + i, offset + i, width - (i * 2), boxHeight - (i*2));
        }

        g.setColor(50, 50, 50);
        if (selected) g.setColor(80, 80, 80);
        g.fillRect(X_PADDING + BTN_DEPTH, offset + BTN_DEPTH, width - (BTN_DEPTH * 2), boxHeight - (BTN_DEPTH*2));

        g.setColor(255, 255, 255);
        g.drawString(text, X_PADDING * 2, offset + (boxHeight / 2), Graphics.VCENTER | Graphics.LEFT);

        return boxHeight * 6 / 5;
    }

    public static int drawWrappedText(Graphics g, String text, int x, int y, int maxWidth) {
        Font font = g.getFont();
        int fontHeight = font.getHeight();
        int currentY = y;
        
        int startIdx = 0;
        int textLength = text.length();

        while (startIdx < textLength) {
            int endIdx = startIdx;
            int lastSpaceIdx = -1;
            
            // Loop through characters to find where the line exceeds maxWidth
            while (endIdx < textLength) {
                char c = text.charAt(endIdx);
                
                if (c == ' ') {
                    lastSpaceIdx = endIdx;
                }
                // Handle manual newlines (\n) if present in the source text
                if (c == '\n') {
                    lastSpaceIdx = endIdx;
                    break;
                }

                // Check pixel width of the substring candidate
                String testLine = text.substring(startIdx, endIdx + 1);
                if (font.stringWidth(testLine) > maxWidth) {
                    break; // Exceeded width limit
                }
                
                endIdx++;
            }

            // Determine the actual chunk of text to render for this line
            String lineToDraw;
            if (endIdx >= textLength) {
                // We reached the very end of the text string
                lineToDraw = text.substring(startIdx);
                startIdx = textLength;
            } else if (text.charAt(endIdx) == '\n') {
                // Hit an explicit newline character
                lineToDraw = text.substring(startIdx, endIdx);
                startIdx = endIdx + 1; // Skip the '\n'
            } else if (lastSpaceIdx > startIdx) {
                // Break cleanly at the last space character encountered
                lineToDraw = text.substring(startIdx, lastSpaceIdx);
                startIdx = lastSpaceIdx + 1; // Skip the space for the next line
            } else {
                // Emergency fallback: Word is longer than maxWidth, force break mid-word
                lineToDraw = text.substring(startIdx, endIdx);
                startIdx = endIdx;
            }

            // Draw the current calculated line
            g.drawString(lineToDraw, x, currentY, Graphics.TOP | Graphics.LEFT);
            
            // Advance the Y coordinate down for the next line
            currentY += fontHeight;
        }
        return currentY - y;
    }
}
