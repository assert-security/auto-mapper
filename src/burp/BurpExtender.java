/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import java.io.InputStreamReader;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import io.swagger.client.ApiException;
import io.swagger.client.model.BurpHttpService;
import io.swagger.client.model.BurpIssueData;
import io.swagger.client.model.BurpIssueHost;
import io.swagger.client.model.BurpIssueRequest;
import io.swagger.client.model.BurpIssueRequestResponse;
import io.swagger.client.model.BurpIssueResponse;
import io.swagger.client.model.BurpMenu;
import io.swagger.client.model.BurpMenuType;
import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.MatchPosition;
import io.swagger.client.model.OperationResultData;

import java.awt.Component;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

//Burp will auto-detect and load any class that extends BurpExtension.
public class BurpExtender implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
    private RestClient _restClient;
    private MontoyaApi _api;
    private String sessionID;

    @Override
    public void initialize(MontoyaApi api) {
        _api = api;
        // set extension name
        api.extension().setName("Auto Mapper");
        Logging logging = api.logging();
        _restClient = new RestClient(logging);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(this);

        try {
            String token = getVenariToken(logging);
            if (token != null && !token.isEmpty()) {
                this.sessionID = _restClient.createBurpSession(token);
                logging.logToOutput("Venari Session ID: " + this.sessionID);
            }

        } catch (IOException ex) {
            logging.logToError(ex.getMessage());
        } catch (ApiException ex) {
            logging.logToError(ex.getMessage());
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

    public static String getVenariToken(Logging logging) throws IOException {
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
            logging.logToOutput("Missing Venari token file.  Run the Venari UI and then reload the extension.");
        }
        return ret;
    }

    private boolean doesMenuNeedTraffic(BurpMenu menu) {
        boolean ret = false;
        try {
            ret = menu.isNeedTraffic();
        } catch (Exception ex) {

        }
        return ret;
    }

    private boolean doesMenuNeedIssues(BurpMenu menu) {
        boolean ret = false;
        try {
            ret = menu.isNeedIssue();
        } catch (Exception ex) {

        }
        return ret;
    }

    private List<Component> createMenuItems(List<BurpMenu> menus, List<HttpRequestResponse> traffic,
            List<AuditIssue> issues) {
        Logging logging = _api.logging();
        List<Component> ret = new ArrayList<>();
        if (menus != null && menus.size() > 0) {
            for (int i = 0; i < menus.size(); i++) {
                BurpMenu menu = menus.get(i);
                if (doesMenuNeedTraffic(menu) && !(traffic.size() > 0)) {
                    continue;
                }
                if (doesMenuNeedIssues(menu) && !(issues.size() > 0)) {
                    continue;
                }
                if (menu.getType() == BurpMenuType.NUMBER_0) {
                    JMenu jmenu = new JMenu(menu.getName());
                    List<BurpMenu> submenus = menu.getSubMenus();
                    List<Component> subjmenus = createMenuItems(submenus, traffic, issues);
                    if (subjmenus != null && subjmenus.size() > 0) {
                        for (int j = 0; j < subjmenus.size(); j++) {
                            jmenu.add(subjmenus.get(j));
                        }
                    }
                    ret.add(jmenu);
                } else {
                    JMenuItem menuItem = new JMenuItem(menu.getName());
                    menuItem.setAction(
                            new VenariMenuAction(menu, _restClient, logging, _api, sessionID, traffic, issues));
                    ret.add(menuItem);
                }
            }
        }
        return ret;
    }

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Logging logging = _api.logging();
        List<Component> menuList = null;
        try {
            logging.logToOutput("Creating Venari menu items...");
            String token = getVenariToken(logging);
            if (token != null && !token.isEmpty()) {
                List<BurpMenu> menus = _restClient.getBurpMenus(token, sessionID);
                menuList = createMenuItems(menus, event.selectedRequestResponses(), event.selectedIssues());
            }
        } catch (Exception ex) {
            logging.logToOutput("Unable to create Venari menu items. " + ex.toString());
        }
        return menuList;
    }

    @Override
    public void extensionUnloaded() {
        Logging logging = _api.logging();
        try {
            logging.logToOutput("Unloading Venari extension...");
            String token = getVenariToken(logging);
            if (token != null && !token.isEmpty()) {
                OperationResultData result = _restClient.closeBurpSession(token, this.sessionID);
                if (result == null || !result.isSucceeded()) {
                    logging.logToOutput("Unable to close Venari burp session. " + result.getMessage());
                }
            }
        } catch (Exception ex) {
            logging.logToOutput("Unable to close Venari burp session. " + ex.toString());
        }
    }

}
