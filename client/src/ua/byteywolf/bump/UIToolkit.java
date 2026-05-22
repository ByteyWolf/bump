package ua.byteywolf.bump;
import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.lcdui.TextBox;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;

import ua.byteywolf.bump.pages.AppPage;

public class UIToolkit {
    // An assortment of ready-to-use UI elements for BUMP.
    // Useful for creating forms.

    public static final int X_PADDING = 5;
    public static final int BTN_DEPTH = 3;

    private static int offset = 0;
    private static Graphics g;
    public static int screenWidth = 0;
    public static int screenHeight = 0;
    private static AppPage crtPage;

    private static int accentR = 0;
    private static int accentG = 0;
    private static int accentB = 0;

    public static int selectedElement = 0;
    public static int elementCount = 0;
    private static int tempCount = 0;
    
    public static int scrollDistance = 0;
    public static int pageHeight = 0;
    private static int tempHeight = 0;

    private static BUMPMessenger midlet = null;

    // text prompting nonsense
    private static final Command SAVE_CMD = new Command("Save", Command.OK, 1);
    private static final Command CANCEL_CMD = new Command("Cancel", Command.CANCEL, 2);
    private static Displayable canvasScreen;
    private static Display display;

    public static void initialize(int newWidth, int newHeight, int newAccentColorRgba, AppPage page, BUMPMessenger creator) {
        screenWidth = newWidth;
        screenHeight = newHeight;

        accentR = ((newAccentColorRgba >> 16) & 0xFF);
        accentG = ((newAccentColorRgba >> 8) & 0xFF);
        accentB = (newAccentColorRgba & 0xFF);

        selectedElement = 0;
        crtPage = page;

        midlet = creator;
        display = Display.getDisplay(midlet);
    }

    // Call this at the start of a painting session.
    // AppUI.java already does this before invoking other page drawing.
    public static void blank(int startOffset, Graphics newGraphics) {
        offset = startOffset - scrollDistance;
        g = newGraphics;
        tempCount = 0;
        tempHeight = -offset;
    }

    // Call this at the finish of a painting session.
    // AppUI.java already does this before invoking other page drawing.
    public static void finish() {
        if (selectedElement >= tempCount) selectedElement = 0;
        elementCount = tempCount;
        pageHeight = tempHeight += offset;
    }

    // Called by AppUI.java
    public static void keyPressed(int action) {
        switch (action) {
            case Canvas.DOWN:
                selectedElement++;
                if (selectedElement >= elementCount) selectedElement = 0;
                break;
            case Canvas.UP:
                selectedElement--;
                if (selectedElement < 0) selectedElement = elementCount - 1;
                break;
            case Canvas.FIRE:
                // handle it yourself bestie
                crtPage.elementSelect(selectedElement);
                break;
        }
    }

    // ==================== [ UI ELEMENTS ] ====================

    public static void Separator(String text) {
        Font ogFont = g.getFont();
        int fontHeight = ogFont.getHeight();
        int objectHeight = fontHeight * 3 / 2;

        if (fitsOnScreen(objectHeight)) {
        g.setColor(128, 128, 128);
        g.drawLine(X_PADDING, offset + objectHeight / 2, screenWidth - X_PADDING, offset + objectHeight / 2);
        int textWidth = ogFont.stringWidth(text);
        g.setColor(0, 0, 0);
        g.fillRect(X_PADDING * 3, offset, textWidth + X_PADDING * 2, objectHeight);
        g.setColor(255, 255, 255);
        g.drawString(text, X_PADDING * 4, offset + (objectHeight - fontHeight) / 2, Graphics.TOP | Graphics.LEFT);
        }

        offset += objectHeight;
    }

    public static void Checkbox(String label, boolean checked) {
        Font ogFont = g.getFont();
        int fontHeight = ogFont.getHeight();
        int boxHeight = fontHeight;
        int necessaryPadding = (boxHeight - fontHeight) / 2;

        if (fitsOnScreen(boxHeight)) {

        boolean selected = (selectedElement == tempCount);
        tempCount++;

        int spacingRight = ogFont.stringWidth(label) + ogFont.charWidth(' ');
        if (label.length() == 0) {spacingRight = 0;}
        else {g.setColor(255, 255, 255); g.drawString(label, X_PADDING, offset + necessaryPadding, Graphics.TOP | Graphics.LEFT);}

        g.setColor(40, 40, 40);
        if (selected) g.setColor(accentR, accentG, accentB);
        g.fillRect(X_PADDING + spacingRight, offset + necessaryPadding, fontHeight, fontHeight);
        g.setColor(20, 20, 20);
        if (selected) g.setColor(50, 50, 50);
        g.fillRect(X_PADDING + spacingRight + 1, offset + necessaryPadding + 1, fontHeight - 2, fontHeight - 2);

        if (checked) {
            g.setColor(accentR, accentG, accentB);
            g.fillRect(X_PADDING + spacingRight + 4, offset + necessaryPadding + 4, fontHeight - 8, fontHeight - 8);
        }
        }

        offset += boxHeight * 6 / 5;
    }

    public static void TextLabel(String text) {
        g.setColor(255, 255, 255);
        offset += drawWrappedText(g, text, X_PADDING, offset, screenWidth - (X_PADDING * 2));
    }

    public static void EntryBox(String label, String textEntered, String defaultText) {
        Font ogFont = g.getFont();
        int fontHeight = ogFont.getHeight();
        int boxHeight = fontHeight * 3 / 2;
        int necessaryPadding = (boxHeight - fontHeight) / 2;

        boolean selected = (selectedElement == tempCount);
        tempCount++;

        if (fitsOnScreen(boxHeight)) {

        int spacingRight = ogFont.stringWidth(label) + ogFont.charWidth(' ');
        if (label.length() == 0) {spacingRight = 0;}
        else {g.setColor(255, 255, 255); g.drawString(label, X_PADDING, offset + necessaryPadding, Graphics.TOP | Graphics.LEFT);}

        g.setColor(40, 40, 40);
        if (selected) g.setColor(accentR, accentG, accentB);
        g.fillRect(X_PADDING + spacingRight, offset, screenWidth - (X_PADDING * 2) - spacingRight, boxHeight);
        g.setColor(20, 20, 20);
        if (selected) g.setColor(50, 50, 50);
        g.fillRect(X_PADDING + spacingRight + 1, offset + 1, screenWidth - (X_PADDING * 2) - 2 - spacingRight, boxHeight - 2);

        g.setColor(255, 255, 255);
        if (textEntered.length() == 0) {
            //Font italicFont = Font.getFont(ogFont.getFace(), Font.STYLE_ITALIC, ogFont.getSize());
            //g.setFont(italicFont);
            textEntered = defaultText;
            g.setColor(150, 150, 150);
        }
        g.drawString(textEntered, X_PADDING * 2 + spacingRight, offset + necessaryPadding, Graphics.TOP | Graphics.LEFT);
        //g.setFont(ogFont);
        }

        offset += boxHeight * 6 / 5;
    }

    public static void TextButton(String text) {
        int fontHeight = g.getFont().getHeight();
        int boxHeight = fontHeight * 3 / 2 + (BTN_DEPTH * 2);
        int width = X_PADDING * 2 + g.getFont().stringWidth(text) + (X_PADDING * 2);
        int necessaryPadding = (boxHeight - fontHeight) / 2;

        if (fitsOnScreen(boxHeight)) {

        boolean selected = (selectedElement == tempCount);
        tempCount++;

        for (int i = 0; i < BTN_DEPTH; i++) {
            safeSetColor(255 / BTN_DEPTH * i, 255 / BTN_DEPTH * i, 255 / BTN_DEPTH * i);
            if (selected) safeSetColor(accentR / BTN_DEPTH * i, accentG / BTN_DEPTH * i, accentB / BTN_DEPTH * i);
            g.fillRect(X_PADDING + i, offset + i, width - (i * 2), boxHeight - (i*2));
        }

        g.setColor(50, 50, 50);
        if (selected) g.setColor(80, 80, 80);
        g.fillRect(X_PADDING + BTN_DEPTH, offset + BTN_DEPTH, width - (BTN_DEPTH * 2), boxHeight - (BTN_DEPTH*2));

        g.setColor(255, 255, 255);
        g.drawString(text, X_PADDING + BTN_DEPTH + (width - (BTN_DEPTH * 2)) / 2, offset + necessaryPadding, Graphics.TOP | Graphics.HCENTER);

        }

        offset += boxHeight * 6 / 5;
    }

    public static void Gap(int height) {
        offset += height;
    }

    // ==================== [ USEFUL ] ====================
    private static boolean fitsOnScreen(int height) {
        if (offset > screenHeight || offset < -height) return false;
        return true;
    }


    public static void promptText(String title, String currentText, int maxSize) {
        promptText(title, currentText, maxSize, -1);
    }


    public static void promptText(String title, String currentText, int maxSize, int constraints) {
        if (constraints == -1) constraints = TextField.ANY;
        canvasScreen = display.getCurrent();

        TextBox textBox = new TextBox(title, currentText, maxSize, constraints);
        textBox.addCommand(SAVE_CMD);
        textBox.addCommand(CANCEL_CMD);
        
        textBox.setCommandListener(new CommandListener() {
            public void commandAction(Command c, Displayable d) {
                if (c == SAVE_CMD && crtPage != null) {
                    String resultText = ((TextBox)d).getString();
                    crtPage.textSaved(selectedElement, resultText);
                }
                display.setCurrent(canvasScreen);
            }
        });

        display.setCurrent(textBox);
    }

    private static void safeSetColor(int r, int gc, int b) {
        if (r < 0) r = 0;
        if (gc < 0) gc = 0;
        if (b < 0) b = 0;
        g.setColor(r & 0xff, gc & 0xff, b & 0xff);
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
