package ua.byteywolf.bump.pages;

import javax.microedition.lcdui.Graphics;

public interface AppPage {
    void paint(Graphics g, int topMargin, int bottomMargin);
    void elementSelect(int elementId);
    void textSaved(int elementId, String text);
    void cleanup();
}