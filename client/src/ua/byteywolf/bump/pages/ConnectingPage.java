package ua.byteywolf.bump.pages;

import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import javax.microedition.lcdui.Graphics;
import javax.microedition.lcdui.Image;

import ua.byteywolf.bump.AppUI;
import ua.byteywolf.bump.BUMPMessenger;
import ua.byteywolf.bump.BUMPProtocol;
import ua.byteywolf.bump.UIToolkit;
import javax.microedition.lcdui.game.Sprite;

public class ConnectingPage implements AppPage {
    public static final ConnectingPage INSTANCE = new ConnectingPage();
    public static final int FRAME_SIZE = 64;

    public static final int MODE_WAIT_FOR_HANDSHAKE = 0;

    private Sprite globeSprite;
    private Timer animationTimer;
    private boolean initialized = false;

    private static int connectMode = 0;

    public void initialize() {
        try {
            if (globeSprite == null) {
                Image sheet = Image.createImage("/res/globe_sheet.png");
                globeSprite = new Sprite(sheet, FRAME_SIZE, FRAME_SIZE);
            }
            startAnimation();
            initialized = true;
        } catch (IOException e) {
            BUMPMessenger.showErrorAndExit("Failed to load app resources");
        }
        
    }

    private void startAnimation() {
        animationTimer = new Timer();
        animationTimer.schedule(new TimerTask() {
            public void run() {
                if (globeSprite != null) {
                    // Advance to the next frame. It loops back to 0 automatically!
                    globeSprite.nextFrame();
                    // Force the phone to redraw the screen
                    AppUI.instance.repaint();
                }

                if (connectMode == MODE_WAIT_FOR_HANDSHAKE) {
                    Exception e = AppUI.messagingApi.lastException;
                    if (AppUI.messagingApi.currentState == BUMPProtocol.STATE_DISCONNECTED) {
                        if (AppUI.messagingApi.currentHandshakeState == BUMPProtocol.HANDSHAKE_STATE_FAILED) {
                            BUMPMessenger.showErrorAndExit("Failed to handshake! Please try again.");
                        } else if (e != null) {
                            BUMPMessenger.showErrorAndExit(e.getClass().getName() + ": " + e.getMessage());
                        }
                    }
                    
                }
            }
        }, 0, 100);
    }

    public void paint(Graphics g, int topMargin, int bottomMargin) {
        if (!initialized) initialize();
        if (globeSprite != null) {
            int centerX = (UIToolkit.screenWidth - FRAME_SIZE) / 2;
            int centerY = UIToolkit.screenHeight / 2 - FRAME_SIZE;

            globeSprite.setPosition(centerX, centerY);
            globeSprite.paint(g);

            g.setColor(255, 255, 255);
            int state = AppUI.messagingApi.currentHandshakeState;
            g.drawString(state == BUMPProtocol.HANDSHAKE_STATE_HELLO ? "Negotiating..." : (state == BUMPProtocol.HANDSHAKE_STATE_AUTH ? "Authenticating..." : "Connecting..."), UIToolkit.screenWidth / 2, UIToolkit.screenHeight / 2 + 10, Graphics.HCENTER | Graphics.TOP);
        }
    }

    public void cleanup() {
        if (animationTimer != null) {
            animationTimer.cancel();
        }
        initialized = false;
    }

    public void elementSelect(int elementId) {
        throw new RuntimeException("Unimplemented method 'elementSelect'");
    }

    public void textSaved(int elementId, String text) {
        // TODO Auto-generated method stub
        throw new RuntimeException("Unimplemented method 'textSaved'");
    }
}
