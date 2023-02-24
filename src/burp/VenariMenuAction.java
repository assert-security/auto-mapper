package burp;

import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.swing.AbstractAction;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import io.swagger.client.ApiException;
import io.swagger.client.model.BurpHttpService;
import io.swagger.client.model.BurpIssue;
import io.swagger.client.model.BurpMenu;
import io.swagger.client.model.BurpMenuType;
import io.swagger.client.model.BurpNotification;
import io.swagger.client.model.BurpNotification.TypeEnum;
import io.swagger.client.model.BurpNotifications;
import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.ExecuteBurpMenuResult;

public class VenariMenuAction extends AbstractAction {
    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private final RestClient restClient;
    private final Logging logging;
    private final String sessionID;
    private final MontoyaApi callbacks;
    private final BurpMenu menu;
    private final List<HttpRequestResponse> traffic;

    public VenariMenuAction(BurpMenu menu, RestClient restClient, Logging logging, MontoyaApi callbacks,
            String sessionID, List<HttpRequestResponse> traffic) {
        super(menu.getName());
        this.menu = menu;
        this.restClient = restClient;
        this.logging = logging;
        this.sessionID = sessionID;
        this.callbacks = callbacks;
        this.traffic = traffic;
    }

    private boolean doesMenuNeedTraffic(BurpMenu menu) {
        boolean ret = false;
        try {
            ret = menu.isNeedTraffic();
        }
        catch (Exception ex) {

        }
        return ret;
    }

    private ExecuteBurpMenuResult executeMenuIfPossible(BurpMenu menu, String token) throws ApiException {
        boolean needTraffic = doesMenuNeedTraffic(menu);
        if (!needTraffic) {
            String menuName = menu.getName();
            ExecuteBurpMenuResult result = restClient.executeBurpMenu(token, sessionID, menu);
            if (result == null) {
                logging.logToOutput("Unable to execute menu: " + menuName + ".  Unknown error.");
            }
            if (!result.isSuccess()) {
                String errorMessage = result.getErrorMessage();
                if (errorMessage == null || errorMessage.length() == 0) {
                    logging.logToOutput("Unable to execute menu: " + menuName + ".  Unknown error.");
                } else {
                    logging.logToOutput("Unable to execute menu: " + menuName + ". " + errorMessage);
                }
            }
            return result;
        }
        return null;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String menuName = menu.getName();
        String applicationName = menu.getApplicationName();
        if (applicationName != null && applicationName.length() > 0) {
            menuName = "[" + applicationName + "]" + menuName;
        }
        try {
            logging.logToOutput("Executing Venari menu: " + menuName);
            String token = BurpExtender.getVenariToken(logging);
            if (token != null && !token.isEmpty()) {
                boolean canProcess = true;
                ExecuteBurpMenuResult result = executeMenuIfPossible(menu, token);
                if (doesMenuNeedTraffic(menu)) {
                    if (this.traffic == null || this.traffic.size() == 0) {
                        logging.logToOutput("Unable to execute menu: " + menuName + ". No HTTP traffic selected.");
                        canProcess = false;
                    }
                    else {
                        logging.logToOutput("Invoking asynchronous menu " + menuName + "...");
                    }
                }
                else if (result == null || !result.isSuccess()) {
                    canProcess = false;
                }
                if (canProcess) {                    
                    final BurpNotifications notifications;
                    final String finishMessage;


                    if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_1) { // Run Scan
                        logging.logToOutput("Started Venari scan for " + menuName + "...");
                        finishMessage = "Finished Venari scan for " + menuName + ".";
                        notifications = null;
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_2) { // Get Site Map
                        logging.logToOutput("Getting site map for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished getting site map for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_3) { // Get Issues
                        logging.logToOutput("Getting issues for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished getting issues for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_4) { // Get Scan
                        logging.logToOutput("Getting scan for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished scan for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_4) { // Send To Venari
                        logging.logToOutput("Sending HTTP traffic to Venari Playground.");
                        List<BurpTraffic> traffic = new ArrayList<BurpTraffic>();
                        restClient.setBurpTraffic(token, traffic);
                        finishMessage = "Executing background task to send HTTP traffic.";
                        logging.logToOutput(finishMessage);
                        notifications = null;
                    } else {
                        notifications = null;
                        finishMessage = "";
                    }
                    Runnable r = new Runnable() {
                        public void run() {
                            Boolean processFlag = true;
                            Integer failCount = 0;
                            while (processFlag) {
                                try {
                                    if (menu.getType() == BurpMenuType.NUMBER_5) {
                                        for (int i=0; i < traffic.size(); i++) {
                                            HttpRequestResponse messageInfo = traffic.get(i);

                                            String method = messageInfo.request().method();
                                            String url = messageInfo.url();      
                                            String host = messageInfo.httpService().host();
                                            int port = messageInfo.httpService().port();
                                            String scheme = "http";
                                            if (messageInfo.httpService().secure())
                                            {
                                                scheme = "https";
                                            }
                                            logging.logToOutput("Sending to playground: (" + method + ") " + url);
                                            BurpTraffic burpTraffic = new BurpTraffic();                                            
                                            burpTraffic.setBase64RequestBytes(callbacks.utilities().base64Utils().encodeToString(messageInfo.request().toByteArray()));
                                            ByteArray responseBytes = messageInfo.response().toByteArray();
                                            if (responseBytes != null && responseBytes.length() > 0) {
                                                burpTraffic.setBase64ResponseBytes(callbacks.utilities().base64Utils().encodeToString(responseBytes));
                                            }
                                            BurpHttpService bHttpService = new BurpHttpService();
                                            bHttpService.setHost(host);
                                            bHttpService.setPort(port);
                                            bHttpService.setScheme(scheme);
                                            burpTraffic.setHttpService(bHttpService);
                                            burpTraffic.setSessionID(sessionID);
                                            List<BurpTraffic> btList = new ArrayList<BurpTraffic>();
                                            btList.add(burpTraffic);
                                            restClient.setBurpTraffic(token, btList);
                                            restClient.executeBurpMenu(token, sessionID, menu);
                                        }
                                        break;
                                    }
                                    else if (result == null) {
                                        break;
                                    }
                                    BurpNotifications scanNotifications = null;
                                    if (notifications == null) {
                                        scanNotifications = restClient.getBurpNotifications(token, sessionID);
                                    } else {
                                        scanNotifications = notifications;
                                    }
                                    if (scanNotifications == null || scanNotifications.isIsComplete()) {
                                        processFlag = false;
                                    }
                                    if (scanNotifications != null) {
                                        List<BurpNotification> changes = scanNotifications.getChanges();
                                        if (changes != null && changes.size() > 0) {
                                            for (int i = 0; i < changes.size(); i++) {
                                                BurpNotification change = changes.get(i);
                                                UUID scanID = menu.getScanID();
                                                if (scanID == null || scanID == UUID
                                                        .fromString("00000000-0000-0000-0000-000000000000")) {
                                                    scanID = result.getScanID();
                                                }
                                                if (change.getType() == TypeEnum.NUMBER_0) { // site map
                                                    List<BurpTraffic> traffic = restClient.getBurpTraffic(token,
                                                            sessionID, change.getID(), scanID);
                                                    if (traffic != null && traffic.size() > 0) {
                                                        for (int j = 0; j < traffic.size(); j++) {
                                                            BurpTraffic trafficItem = traffic.get(j);
                                                            HttpRequestResponse messageInfo = new RequestResponse(
                                                                    trafficItem, callbacks);
                                                            String method = messageInfo.request().method();
                                                            String url = messageInfo.url();
                                                            logging.logToOutput("Adding to site map: (" + method + ") " + url);
                                                            callbacks.siteMap().add(messageInfo);
                                                        }
                                                    }
                                                } else if (change.getType() == TypeEnum.NUMBER_1) { // issue
                                                    String applicationName = menu.getApplicationName();
                                                    if (applicationName == null || applicationName.length() == 0) {
                                                        applicationName = menu.getName();
                                                    }
                                                    BurpIssue burpIssue = restClient.getBurpIssue(token, sessionID,
                                                            change.getID(), applicationName, scanID);
                                                    if (burpIssue != null) {
                                                        AuditIssue issue = new Issue(burpIssue, callbacks);
                                                        logging.logToOutput("Found issue: " + issue.name());
                                                        List<HttpRequestResponse> httpMessages = issue.requestResponses();
                                                        if (httpMessages != null && httpMessages.size() > 0) {
                                                            logging.logToOutput("Issue locations:");
                                                            for (int j = 0; j < httpMessages.size(); j++) {
                                                                HttpRequestResponse messageInfo = httpMessages.get(j);
                                                                String method = messageInfo.request().method();
                                                                String url = messageInfo.url();
                                                                logging.logToOutput("  (" + method + ") "
                                                                        + url);
                                                            }
                                                        }
                                                        callbacks.siteMap().add(issue);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } catch (Exception innerEx) {
                                    logging.logToOutput("Error retrieving Venari notifications. " + innerEx.getMessage());
                                    failCount++;
                                }
                                try {
                                    Thread.sleep(2000);
                                } catch (Exception ex) {
                                    logging.logToOutput(("Thread sleep failed. " + ex.toString()));
                                }
                                if (failCount > 10) {
                                    processFlag = false;
                                }
                            }
                            logging.logToOutput(finishMessage);
                        }
                    };
                    new Thread(r).start();
                }
            }
        } catch (Exception ex) {
            logging.logToOutput("Unable to execute Venari menu " + menuName + ". " + ex.toString());
        }

    }
}