package burp;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

import io.swagger.client.model.BurpHttpService;
import io.swagger.client.model.BurpIssue;
import io.swagger.client.model.BurpTraffic;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public class Issue implements AuditIssue {

    private final BurpIssue issue;
    private final List<HttpRequestResponse> httpMessages;

    public Issue(BurpIssue issue, MontoyaApi callbacks) throws MalformedURLException {
        this.issue = issue;
        List<HttpRequestResponse> list = new ArrayList<HttpRequestResponse>();
        List<BurpTraffic> traffic = this.issue.getTraffic();
        if (traffic != null && traffic.size() > 0) {
            for (int i=0; i<traffic.size(); i++) {
                BurpTraffic trafficItem = traffic.get(i);
                HttpRequestResponse messageInfo = new RequestResponse(trafficItem, callbacks);
                list.add(messageInfo);
            }
        }
        this.httpMessages = list;
    }

    @Override
    public HttpService httpService() {
        BurpHttpService httpService = this.issue.getHttpService();
        Boolean secure = false;
        if (httpService.getScheme().startsWith("https"))
        {
            secure = true;
        }
        return HttpService.httpService(httpService.getHost(), httpService.getPort(), secure);
    }

    @Override
    public String baseUrl() {
        return httpService().toString();
    }

    @Override
    public String name() {
        return issue.getName();
    }

    @Override
    public String detail() {
        return issue.getDescription();
    }

    @Override
    public String remediation() {
        return null;
    }

    @Override
    public AuditIssueSeverity severity() {
        String severity = issue.getSeverity();
        if (severity == "Critical" || severity == "High") 
        {
            return AuditIssueSeverity.HIGH;
        }
        else if (severity == "Medium") 
        {
            return AuditIssueSeverity.MEDIUM;
        }
        else if (severity == "Low")
        {
            return AuditIssueSeverity.LOW;
        }
        else
        {
            return AuditIssueSeverity.INFORMATION;
        }
    }

    @Override
    public AuditIssueConfidence confidence() {
        String confidence = issue.getConfidence();
        if (confidence == "Tentative")
        {
            return AuditIssueConfidence.TENTATIVE;
        }
        else
        {
            return AuditIssueConfidence.CERTAIN;
        }
    }

    @Override
    public List<HttpRequestResponse> requestResponses() {
        return this.httpMessages;
    }

    @Override
    public AuditIssueDefinition definition() {
        return AuditIssueDefinition.auditIssueDefinition(name(), detail(), null, severity());
    }

}