package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import io.swagger.client.model.BurpIssue;
import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.MatchPosition;

public class Issue implements IScanIssue {

    private final BurpIssue issue;
    private URL url;
    private final IHttpRequestResponse[] httpMessages;

    public Issue(BurpIssue issue, IBurpExtenderCallbacks callbacks) throws MalformedURLException {
        this.issue = issue;
        String urlText = issue.getUrl();
        if (urlText != null && urlText.length() > 0) {
            this.url = new URL(issue.getUrl());
        }
        List<IHttpRequestResponse> list = new ArrayList<IHttpRequestResponse>();
        List<BurpTraffic> traffic = this.issue.getTraffic();
        if (traffic != null && traffic.size() > 0) {
            for (int i=0; i<traffic.size(); i++) {
                BurpTraffic trafficItem = traffic.get(i);
                IHttpRequestResponseWithMarkers messageInfo = new RequestResponse(trafficItem, callbacks);
                list.add(messageInfo);
            }
        }
        this.httpMessages = list.toArray(new IHttpRequestResponse[list.size()]);
    }

    @Override
    public URL getUrl() {
        return this.url;
    }

    @Override
    public String getIssueName() {
        return issue.getName();
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return this.issue.getSeverity();
    }

    @Override
    public String getConfidence() {
        return this.issue.getConfidence();
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return this.issue.getDescription();
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return this.httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return new HttpService(this.issue.getHttpService());
    }

}