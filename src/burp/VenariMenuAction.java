package burp;

import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.swing.AbstractAction;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.core.Marker;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.HttpService;

import io.swagger.client.ApiException;
import io.swagger.client.model.BurpHttpService;
import io.swagger.client.model.BurpIssue;
import io.swagger.client.model.BurpIssueData;
import io.swagger.client.model.BurpIssueHost;
import io.swagger.client.model.BurpIssueRequest;
import io.swagger.client.model.BurpIssueRequestResponse;
import io.swagger.client.model.BurpIssueResponse;
import io.swagger.client.model.BurpMenu;
import io.swagger.client.model.BurpMenuType;
import io.swagger.client.model.BurpNotification;
import io.swagger.client.model.BurpNotification.TypeEnum;
import io.swagger.client.model.BurpNotifications;
import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.ExecuteBurpMenuResult;
import io.swagger.client.model.MatchPosition;

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
    private final List<AuditIssue> issues;

    public VenariMenuAction(BurpMenu menu, RestClient restClient, Logging logging, MontoyaApi callbacks,
            String sessionID, List<HttpRequestResponse> traffic, List<AuditIssue> issues) {
        super(menu.getName());
        this.menu = menu;
        this.restClient = restClient;
        this.logging = logging;
        this.sessionID = sessionID;
        this.callbacks = callbacks;
        this.traffic = traffic;
        this.issues = issues;
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

    private boolean doesMenuNeedIssues(BurpMenu menu) {
        boolean ret = false;
        try {
            ret = menu.isNeedIssue();
        }
        catch (Exception ex) {

        }
        return ret;
    }

    private ExecuteBurpMenuResult executeMenuIfPossible(BurpMenu menu, String token) throws ApiException {
        boolean needTraffic = doesMenuNeedTraffic(menu);
        boolean needIssues = doesMenuNeedIssues(menu);
        if (!needTraffic && !needIssues) {
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

    private List<MatchPosition> createMatchPositionsFromMarkers(List<Marker> markers) {
        List<MatchPosition> list = new ArrayList<MatchPosition>();
        if (markers != null && markers.size() > 0) {
            for (int i = 0; i < markers.size(); i++) {
                Marker marker = markers.get(i);
                MatchPosition matchPosition = new MatchPosition();
                matchPosition.index(marker.range().startIndexInclusive());
                matchPosition.length(marker.range().endIndexExclusive() - marker.range().startIndexInclusive());
                list.add(matchPosition);
            }
        }
        if (list.size() > 0) {
            return list;
        }
        return null;
    }

    private BurpIssueData createBurpIssueFromAuditIssue(AuditIssue issue, Logging logging) {
        BurpIssueData burpIssue = new BurpIssueData();
        burpIssue.name(issue.name());
        burpIssue.severity(issue.severity().name());
        HttpService httpService = issue.httpService();
        if (httpService != null) {
            BurpIssueHost host = new BurpIssueHost();
            String h = httpService.host();
            int port = httpService.port();
            String scheme = "http://";
            if (httpService.secure()) {
                scheme = "https://";
            }
            String endpoint = scheme + h;
            if (port != 80 && port != 443)
            {
                endpoint = endpoint + ":" + String.valueOf(port);
            }
            host.value(endpoint);
            burpIssue.host(host);
        }
        String detail = issue.detail();
        if (detail != null && detail.length() > 0) {
            burpIssue.issueDetail(detail);
        }
        String remediation = issue.remediation();
        if (remediation != null && remediation.length() > 0) {
            burpIssue.remediationDetail(remediation);
        }
        AuditIssueDefinition definition = issue.definition();
        if (definition != null) {
            String background = definition.background();
            if (background != null & background.length() > 0) {
                burpIssue.issueBackground(background);
            }
        }
        List<HttpRequestResponse> traffic = issue.requestResponses();
        if (traffic != null && traffic.size() > 0) {
            ArrayList<BurpIssueRequestResponse> list = new ArrayList<BurpIssueRequestResponse>();
            for (int i = 0; i < traffic.size(); i++) {
                HttpRequestResponse messageInfo = traffic.get(i);

                String method = messageInfo.request().method();
                String url = messageInfo.request().url();
                String host = messageInfo.httpService().host();
                int port = messageInfo.httpService().port();
                String scheme = "http";
                if (messageInfo.httpService().secure()) {
                    scheme = "https";
                }
                logging.logToOutput("Sending to playground: (" + method + ") " + url);
                BurpTraffic burpTraffic = new BurpTraffic();
                burpTraffic.setBase64RequestBytes(
                        callbacks.utilities().base64Utils().encodeToString(messageInfo.request().toByteArray()));
                ByteArray responseBytes = messageInfo.response().toByteArray();
                if (responseBytes != null && responseBytes.length() > 0) {
                    burpTraffic
                            .setBase64ResponseBytes(callbacks.utilities().base64Utils().encodeToString(responseBytes));
                }
                BurpHttpService bHttpService = new BurpHttpService();
                bHttpService.setHost(host);
                bHttpService.setPort(port);
                bHttpService.setScheme(scheme);
                burpTraffic.setHttpService(bHttpService);
                burpTraffic.setSessionID(sessionID);
                BurpIssueRequestResponse burprr = new BurpIssueRequestResponse();
                if (messageInfo.request() != null) {
                    burprr.httpService(burpTraffic.getHttpService());
                    BurpIssueRequest request = new BurpIssueRequest();
                    request.isBase64(true);
                    request.text(burpTraffic.getBase64RequestBytes());
                    request.method(messageInfo.request().method());
                    burprr.request(request);
                    if (messageInfo.response() != null) {
                        BurpIssueResponse response = new BurpIssueResponse();
                        response.isBase64(true);
                        response.text(burpTraffic.getBase64ResponseBytes());
                        burprr.response(response);
                    }
                }
                List<Marker> requestMarkers = messageInfo.requestMarkers();
                burprr.setRequestMarkers(createMatchPositionsFromMarkers(requestMarkers));
                List<Marker> responseMarkers = messageInfo.responseMarkers();
                burprr.setResponseMarkers(createMatchPositionsFromMarkers(responseMarkers));
                list.add(burprr);
            }
            if (list.size() > 0) {
                burpIssue.requestResponses(list);
            }
        }
        return burpIssue;
    }

    private AuditIssueSeverity convertSeverityFromString(String severity) {
        if (severity.toLowerCase().contains("critical") || severity.toLowerCase().contains("high")) 
        {
            return AuditIssueSeverity.HIGH;
        }
        else if (severity.toLowerCase().contains("Medium")) 
        {
            return AuditIssueSeverity.MEDIUM;
        }
        else if (severity.toLowerCase().contains("Low"))
        {
            return AuditIssueSeverity.LOW;
        }
        else
        {
            return AuditIssueSeverity.INFORMATION;
        }
    }
    
    private AuditIssueConfidence convertConfidenceFromString(String confidence) {
        if (confidence == "Tentative")
        {
            return AuditIssueConfidence.TENTATIVE;
        }
        else
        {
            return AuditIssueConfidence.CERTAIN;
        }
    }

    private HttpRequestResponse convertToRequestResponse(BurpTraffic trafficItem) {
        Boolean secure = false;
        if (trafficItem.getHttpService().getScheme().startsWith("https"))
        {
            secure = true;
        }
        HttpService httpService = HttpService.httpService(trafficItem.getHttpService().getHost(), trafficItem.getHttpService().getPort(), secure);
        ByteArray requestBytes = callbacks.utilities().base64Utils().decode(trafficItem.getBase64RequestBytes());
        ByteArray responseBytes = callbacks.utilities().base64Utils().decode(trafficItem.getBase64ResponseBytes());
        HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
        HttpResponse response = HttpResponse.httpResponse(responseBytes);
        List<MatchPosition> reqMarkerList = trafficItem.getRequestMatches();
        List<Marker> requestMarkers = null;
        if (reqMarkerList != null && reqMarkerList.size() > 0) {
            requestMarkers = convertToMarkers(reqMarkerList);

        }
        List<MatchPosition> respMarkerList = trafficItem.getResponseMatches();
        List<Marker> responseMarkers = null;
        if (respMarkerList != null && respMarkerList.size() > 0) {
            responseMarkers = convertToMarkers(respMarkerList);
        }   
        HttpRequestResponse ret =  HttpRequestResponse.httpRequestResponse(request, response);
        if (requestMarkers != null) {
            ret = ret.withRequestMarkers(requestMarkers);
        }
        if (responseMarkers != null) {
            ret = ret.withResponseMarkers(responseMarkers);
        }
        return ret;
    }

    private List<Marker> convertToMarkers(List<MatchPosition> matches) {
        List<Marker> ret = null;
        ArrayList<Marker> list = new ArrayList<Marker>();
        if (matches != null && matches.size() > 0) {
            for (int i = 0; i < matches.size(); i++) {
                MatchPosition match = matches.get(i);
                list.add(Marker.marker(match.getIndex(), match.getIndex() + match.getLength()));
            }
        }
        if (list.size() > 0) {
            ret = list;
        }
        return ret;
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
                else if (doesMenuNeedIssues(menu)) {
                    if (this.issues == null || this.issues.size() == 0) {
                        logging.logToOutput("Unable to execute menu: " + menuName + ". No issues selected.");
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
                                            String url = messageInfo.request().url();      
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
                                    else if (menu.getType() == BurpMenuType.NUMBER_6) {
                                        for (int i=0; i < issues.size(); i++) {
                                            AuditIssue issue = issues.get(i);
                                            BurpIssueData burpIssue = createBurpIssueFromAuditIssue(issue, logging);
                                            logging.logToOutput("Sending to issue to Venari: " + issue.name());
                                            List<BurpIssueData> issueList = new ArrayList<BurpIssueData>();
                                            issueList.add(burpIssue);
                                            restClient.setBurpIssues(token, sessionID, issueList);
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
                                                            HttpRequestResponse messageInfo = convertToRequestResponse(trafficItem);
                                                            String method = messageInfo.request().method();
                                                            String url = messageInfo.request().url();
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
                                                        List<HttpRequestResponse> list = new ArrayList<HttpRequestResponse>();
                                                        List<BurpTraffic> traffic = burpIssue.getTraffic();
                                                        if (traffic != null && traffic.size() > 0) {
                                                            for (int j=0; j<traffic.size(); j++) {
                                                                BurpTraffic trafficItem = traffic.get(j);                                                                
                                                                HttpRequestResponse messageInfo = convertToRequestResponse(trafficItem);
                                                                list.add(messageInfo);
                                                            }
                                                        }
                                                
                                                        AuditIssueSeverity severity = convertSeverityFromString(burpIssue.getSeverity());
                                                        AuditIssue issue = AuditIssue.auditIssue(burpIssue.getName(),
                                                          burpIssue.getDescription(), 
                                                          null, 
                                                          burpIssue.getUrl(), 
                                                          severity,
                                                          convertConfidenceFromString(burpIssue.getConfidence()),
                                                          null, null, severity, list);
                                                        logging.logToOutput("Found issue: " + issue.name() + " Severity: '" + burpIssue.getSeverity() + "'");
                                                        List<HttpRequestResponse> httpMessages = issue.requestResponses();
                                                        if (httpMessages != null && httpMessages.size() > 0) {
                                                            logging.logToOutput("Issue locations:");
                                                            for (int j = 0; j < httpMessages.size(); j++) {
                                                                HttpRequestResponse messageInfo = httpMessages.get(j);
                                                                String method = messageInfo.request().method();                                                                
                                                                String url = messageInfo.request().url();
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