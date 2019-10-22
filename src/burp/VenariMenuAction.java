package burp;

import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.List;

import javax.swing.AbstractAction;

import io.swagger.client.model.BurpIssue;
import io.swagger.client.model.BurpMenu;
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

    public VenariMenuAction(BurpMenu menu, RestClient restClient, PrintWriter stdout, IBurpExtenderCallbacks callbacks,
            String sessionID) {
        super(menu.getName());
        this.menu = menu;
        this.restClient = restClient;
        this.stdout = stdout;
        this.sessionID = sessionID;
        this.callbacks = callbacks;
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
                } else {
                    final BurpNotifications notifications;
                    final String finishMessage;
                    if (menu.getType() == io.swagger.client.model.BurpMenu.TypeEnum.NUMBER_1) { // Run Scan
                        stdout.println("Started Venari scan for " + menuName + "...");
                        finishMessage = "Finished Venari scan for " + menuName + ".";
                        notifications = null;
                    } else if (menu.getType() == io.swagger.client.model.BurpMenu.TypeEnum.NUMBER_2) { // Get Site Map
                        stdout.println("Getting site map for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished getting site map for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenu.TypeEnum.NUMBER_3) { // Get Issues
                        stdout.println("Getting issues for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished getting issues for " + menuName + ".";
                    } else if (menu.getType() == io.swagger.client.model.BurpMenu.TypeEnum.NUMBER_4) { // Get Scan
                        stdout.println("Getting scan for " + menuName + "...");
                        notifications = new BurpNotifications();
                        notifications.setIsComplete(true);
                        notifications.setChanges(result.getResultIds());
                        finishMessage = "Finished scan for " + menuName + ".";
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
                                        if (changes == null) {
                                            stdout.println("changes is null");
                                        } else if (changes.size() == 0) {
                                            stdout.println("changes is empty");
                                        }
                                        if (changes != null && changes.size() > 0) {
                                            for (int i = 0; i < changes.size(); i++) {
                                                BurpNotification change = changes.get(i);
                                                if (change.getType() == TypeEnum.NUMBER_0) { // site map
                                                    List<BurpTraffic> traffic = restClient.getBurpTraffic(token,
                                                            sessionID, change.getID(), menu.getScanID());
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
                                                            change.getID(), applicationName, menu.getScanID());
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