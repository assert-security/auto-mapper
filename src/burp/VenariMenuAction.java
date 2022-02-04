package burp;

import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.swing.AbstractAction;

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
    private final PrintWriter stdout;
    private final String sessionID;
    private final IBurpExtenderCallbacks callbacks;
    private final BurpMenu menu;
    private final List<IHttpRequestResponse> traffic;

    public VenariMenuAction(BurpMenu menu, RestClient restClient, PrintWriter stdout, IBurpExtenderCallbacks callbacks,
            String sessionID, List<IHttpRequestResponse> traffic) {
        super(menu.getName());
        this.menu = menu;
        this.restClient = restClient;
        this.stdout = stdout;
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
                stdout.println("Unable to execute menu: " + menuName + ".  Unknown error.");
            }
            if (!result.isSuccess()) {
                String errorMessage = result.getErrorMessage();
                if (errorMessage == null || errorMessage.length() == 0) {
                    stdout.println("Unable to execute menu: " + menuName + ".  Unknown error.");
                } else {
                    stdout.println("Unable to execute menu: " + menuName + ". " + errorMessage);
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
            stdout.println("Executing Venari menu: " + menuName);
            String token = BurpExtender.getVenariToken(stdout);
            if (token != null && !token.isEmpty()) {
                boolean canProcess = true;
                ExecuteBurpMenuResult result = executeMenuIfPossible(menu, token);
                if (doesMenuNeedTraffic(menu)) {
                    if (this.traffic == null || this.traffic.size() == 0) {
                        stdout.println("Unable to execute menu: " + menuName + ". No HTTP traffic selected.");
                        canProcess = false;
                    }
                    else {
                        stdout.println("Invoking asynchronous menu " + menuName + "...");
                    }
                }
                else if (result == null || !result.isSuccess()) {
                    canProcess = false;
                }
                if (canProcess) {                    
                    final BurpNotifications notifications;
                    final String finishMessage;


                    if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_1) { // Run Scan
                        stdout.println("Started Venari scan for " + menuName + "...");
                        finishMessage = "Finished Venari scan for " + menuName + ".";
                        notifications = null;
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_2) { // Get Site Map
                        stdout.println("Getting site map for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished getting site map for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_3) { // Get Issues
                        stdout.println("Getting issues for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished getting issues for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_4) { // Get Scan
                        stdout.println("Getting scan for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished scan for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenuType.NUMBER_4) { // Send To Venari
                        stdout.println("Sending HTTP traffic to Venari Playground.");
                        List<BurpTraffic> traffic = new ArrayList<BurpTraffic>();
                        restClient.setBurpTraffic(token, traffic);
                        finishMessage = "Executing background task to send HTTP traffic.";
                        stdout.println(finishMessage);
                        notifications = null;
                    } else {
                        notifications = null;
                        finishMessage = "";
                    }
                    final List<IHttpRequestResponse> traffic = this.traffic;
                    Runnable r = new Runnable() {
                        public void run() {
                            Boolean processFlag = true;
                            Integer failCount = 0;
                            while (processFlag) {
                                try {
                                    if (menu.getType() == BurpMenuType.NUMBER_5) {
                                        for (int i=0; i < traffic.size(); i++) {
                                            IHttpRequestResponse messageInfo = traffic.get(i);
                                            IExtensionHelpers helpers = callbacks.getHelpers();

                                            IHttpService httpService = messageInfo.getHttpService();
                                            IRequestInfo requestInfo = helpers.analyzeRequest(httpService,
                                                    messageInfo.getRequest());
                                            stdout.println("Sending to playground: (" + requestInfo.getMethod() + ") " + requestInfo.getUrl());
                                            BurpTraffic burpTraffic = new BurpTraffic();                                            
                                            burpTraffic.setBase64RequestBytes(helpers.base64Encode(messageInfo.getRequest()));
                                            byte[] responseBytes = messageInfo.getResponse();
                                            if (responseBytes != null && responseBytes.length > 0) {
                                                burpTraffic.setBase64ResponseBytes(helpers.base64Encode(responseBytes));
                                            }
                                            BurpHttpService bHttpService = new BurpHttpService();
                                            bHttpService.setHost(httpService.getHost());
                                            bHttpService.setPort(httpService.getPort());
                                            bHttpService.setScheme(httpService.getProtocol());
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
                                                            IHttpRequestResponse messageInfo = new RequestResponse(
                                                                    trafficItem, callbacks);
                                                            IRequestInfo requestInfo = callbacks.getHelpers()
                                                                    .analyzeRequest(messageInfo.getHttpService(),
                                                                            messageInfo.getRequest());
                                                            stdout.println(
                                                                    "Adding to site map: (" + requestInfo.getMethod()
                                                                            + ") " + requestInfo.getUrl());
                                                            callbacks.addToSiteMap(messageInfo);
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
                                                        IScanIssue issue = new Issue(burpIssue, callbacks);
                                                        stdout.println("Found issue: " + issue.getIssueName());
                                                        IHttpRequestResponse[] httpMessages = issue.getHttpMessages();
                                                        if (httpMessages != null && httpMessages.length > 0) {
                                                            stdout.println("Issue locations:");
                                                            for (int j = 0; j < httpMessages.length; j++) {
                                                                IHttpRequestResponse messageInfo = httpMessages[j];
                                                                IRequestInfo requestInfo = callbacks.getHelpers()
                                                                        .analyzeRequest(messageInfo.getHttpService(),
                                                                                messageInfo.getRequest());
                                                                stdout.println("  (" + requestInfo.getMethod() + ") "
                                                                        + requestInfo.getUrl());
                                                            }
                                                        }
                                                        callbacks.addScanIssue(issue);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } catch (Exception innerEx) {
                                    stdout.println("Error retrieving Venari notifications. " + innerEx.getMessage());
                                    failCount++;
                                }
                                try {
                                    Thread.sleep(2000);
                                } catch (Exception ex) {
                                    stdout.println(("Thread sleep failed. " + ex.toString()));
                                }
                                if (failCount > 10) {
                                    processFlag = false;
                                }
                            }
                            stdout.println(finishMessage);
                        }
                    };
                    new Thread(r).start();
                }
            }
        } catch (Exception ex) {
            stdout.println("Unable to execute Venari menu " + menuName + ". " + ex.toString());
        }

    }
}