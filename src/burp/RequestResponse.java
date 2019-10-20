package burp;

import java.util.ArrayList;
import java.util.List;

import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.MatchPosition;

public class RequestResponse implements IHttpRequestResponseWithMarkers {

    private IHttpService httpService;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private List<int[]> requestMarkers;
    private List<int[]> responseMarkers;

    public RequestResponse(BurpTraffic trafficItem, IBurpExtenderCallbacks callbacks) {
        this.httpService = new HttpService(trafficItem.getHttpService());
        this.requestBytes = callbacks.getHelpers().base64Decode(trafficItem.getBase64RequestBytes());
        this.responseBytes = callbacks.getHelpers().base64Decode(trafficItem.getBase64ResponseBytes());
        this.requestMarkers = convertToMarkers(trafficItem.getRequestMatches());
        this.responseMarkers = convertToMarkers(trafficItem.getResponseMatches());
    }

    @Override
    public byte[] getRequest() {
        return requestBytes;
    }

    @Override
    public void setRequest(byte[] message) {
        requestBytes = message;

    }

    @Override
    public byte[] getResponse() {
        return responseBytes;
    }

    @Override
    public void setResponse(byte[] message) {
        responseBytes = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;

    }

    @Override
    public List<int[]> getRequestMarkers() {
        return this.requestMarkers;
    }

    @Override
    public List<int[]> getResponseMarkers() {
        return this.responseMarkers;
    }

    private List<int[]> convertToMarkers(List<MatchPosition> matches) {
        List<int[]> ret = null;
        ArrayList<int[]> list = new ArrayList<int[]>();
        if (matches != null && matches.size() > 0) {
            for (int i = 0; i < matches.size(); i++) {
                MatchPosition match = matches.get(i);
                list.add(new int[] { match.getIndex(), match.getIndex() + match.getLength() });
            }
        }
        if (list.size() > 0) {
            ret = list;
        }
        return ret;
    }

}