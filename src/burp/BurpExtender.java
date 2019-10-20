package burp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import io.swagger.client.model.BurpMenu;
import io.swagger.client.model.BurpMenu.TypeEnum;
import io.swagger.client.model.OperationResultData;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private String sessionID;

    private RestClient restClient;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        try {
            // keep a reference to our callbacks object
            this.callbacks = callbacks;
            // set our extension name
            callbacks.setExtensionName("Auto Mapper");

            // obtain our output stream
            stdout = new PrintWriter(callbacks.getStdout(), true);

            restClient = new RestClient(stdout);
            // register ourselves as a Proxy listener
            callbacks.registerContextMenuFactory(this);
            callbacks.registerExtensionStateListener(this);

            String token = getVenariToken(stdout);
            if (token != null && !token.isEmpty()) {
                this.sessionID = restClient.createBurpSession(token);
                stdout.println("Venari Session ID: " + this.sessionID);
            }

        } catch (Exception ex) {
            stdout.println("Unable to register Venari extension. " + ex.toString());

        }
    }

    public static String getVenariToken(PrintWriter stdout) throws IOException {
        String ret = null;
        String property = "java.io.tmpdir";
        String tempDir = System.getProperty(property);
        Path tokenFile = Paths.get(tempDir, "assert-localserver-token.txt");
        if (Files.exists(tokenFile)) {
            final InputStream targetStream = new FileInputStream(tokenFile.toString());
            try {
                ret = readStream(targetStream);
            } finally {
                targetStream.close();
            }
        } else {
            stdout.println("Missing Venari token file.  Run the Venari UI and then reload the extension.");
        }
        return ret;
    }

    @Override
    public void extensionUnloaded() {
        try {
            stdout.println("Unloading Venari extension...");
            String token = getVenariToken(stdout);
            if (token != null && !token.isEmpty()) {
                OperationResultData result = restClient.closeBurpSession(token, this.sessionID);
                if (result == null || !result.isSucceeded()) {
                    stdout.println("Unable to close Venari burp session. " + result.getMessage());
                }
            }
        } catch (Exception ex) {
            stdout.println("Unable to close Venari burp session. " + ex.toString());
        }
    }

    private static String readStream(InputStream is) {
        StringBuilder sb = new StringBuilder(512);
        try {
            Reader r = new InputStreamReader(is, "UTF-8");
            int c = 0;
            while ((c = r.read()) != -1) {
                sb.append((char) c);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return sb.toString();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = null;
        try {
            stdout.println("Creating Venari menu items...");
            String token = getVenariToken(stdout);
            if (token != null && !token.isEmpty()) {
                List<BurpMenu> menus = restClient.getBurpMenus(token, sessionID);
                menuList = createMenuItems(menus);
            }
        } catch (Exception ex) {
            stdout.println("Unable to create Venari menu items. " + ex.toString());
        }
        return menuList;
    }

    private List<JMenuItem> createMenuItems(List<BurpMenu> menus) {
        List<JMenuItem> ret = new ArrayList<>();
        if (menus != null && menus.size() > 0) {
            for (int i=0; i<menus.size(); i++) {
                BurpMenu menu = menus.get(i);
                if (menu.getType() == TypeEnum.NUMBER_0) {
                    JMenu jmenu = new JMenu(menu.getName());
                    List<BurpMenu> submenus = menu.getSubMenus();
                    List<JMenuItem> subjmenus = createMenuItems(submenus);
                    if (subjmenus != null && subjmenus.size() > 0) {
                        for (int j=0; j<subjmenus.size(); j++) {
                            jmenu.add(subjmenus.get(j));
                        }
                    }
                    ret.add(jmenu);
                }
                else {
                    JMenuItem menuItem = new JMenuItem(menu.getName());
                    menuItem.setAction(new VenariMenuAction(menu, restClient, stdout, callbacks, sessionID));
                    ret.add(menuItem);
                }
            }
        }
        return ret;
    }
}