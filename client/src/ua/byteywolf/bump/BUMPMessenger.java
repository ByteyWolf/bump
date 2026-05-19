package ua.byteywolf.bump;
import javax.microedition.midlet.*;
import javax.microedition.lcdui.*;

public class BUMPMessenger extends MIDlet implements CommandListener {
    private Display display;
    private AppUI ui;
    private static BUMPMessenger instance;
    
    public void startApp() {
        instance = this;
        display = Display.getDisplay(this);
        ui = new AppUI(this);
        display.setCurrent(ui);
    }
    
    public void pauseApp() {}
    
    public void destroyApp(boolean unconditional) {}

    public static void showErrorAndExit(String message) {
        Alert errorAlert = new Alert("Application Error", message, null, AlertType.ERROR);
        errorAlert.setTimeout(Alert.FOREVER);
        errorAlert.setCommandListener(instance);
        instance.display.setCurrent(errorAlert);
    }

    public void commandAction(Command c, Displayable d) {
        destroyApp(true);
        notifyDestroyed();
    }
}
