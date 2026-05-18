import javax.microedition.midlet.*;
import javax.microedition.lcdui.*;

public class BUMPMessenger extends MIDlet {
    private Display display;
    private AppUI ui;
    
    public void startApp() {
        display = Display.getDisplay(this);
        ui = new AppUI();
        display.setCurrent(ui);
    }
    
    public void pauseApp() {}
    
    public void destroyApp(boolean unconditional) {}
}
