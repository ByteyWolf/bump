import javax.microedition.midlet.*;
import javax.microedition.lcdui.*;

public class BUMPMessenger extends MIDlet {
    private Display display;
    private Form form;
    
    public void startApp() {
        display = Display.getDisplay(this);
        form = new Form("Test");
        form.append("Awooooooooooo!");
        display.setCurrent(form);
    }
    
    public void pauseApp() {}
    
    public void destroyApp(boolean unconditional) {}
}
