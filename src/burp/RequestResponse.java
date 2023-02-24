package burp;

import java.util.ArrayList;
import java.util.List;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.MatchPosition;

public class RequestResponse implements HttpRequestResponse {

    private HttpService httpService;
    private HttpRequest request;
    private HttpResponse response;
    private List<Marker> requestMarkers;
    private List<Marker> responseMarkers;

    public RequestResponse(BurpTraffic trafficItem, MontoyaApi api) {
        Boolean secure = false;
        if (trafficItem.getHttpService().getScheme().startsWith("https"))
        {
            secure = true;
        }
        this.httpService = HttpService.httpService(trafficItem.getHttpService().getHost(), trafficItem.getHttpService().getPort(), secure);
        ByteArray requestBytes = api.utilities().base64Utils().decode(trafficItem.getBase64RequestBytes());
        ByteArray responseBytes = api.utilities().base64Utils().decode(trafficItem.getBase64ResponseBytes());
        this.request = HttpRequest.httpRequest(this.httpService, requestBytes);
        this.response = HttpResponse.httpResponse(responseBytes);
        this.requestMarkers = convertToMarkers(trafficItem.getRequestMatches());
        this.responseMarkers = convertToMarkers(trafficItem.getResponseMatches());
    }

    @Override
    public HttpRequest request() {
        return this.request;
    }

    @Override
    public HttpResponse response() {
        return this.response;
    }

    @Override
    public HttpService httpService() {
        return this.httpService;
    }

    @Override
    public List<Marker> requestMarkers() {
        return this.requestMarkers;
    }

    @Override
    public List<Marker> responseMarkers() {
        return this.responseMarkers;
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
    public Annotations annotations() {
        return Annotations.annotations();
    }

    @Override
    public String url() {
        return this.request().url();
    }

    @Override
    public ContentType contentType() {
        throw new UnsupportedOperationException("Unimplemented method 'contentType'");
    }

    @Override
    public short statusCode() {
        throw new UnsupportedOperationException("Unimplemented method 'statusCode'");
    }

    @Override
    public HttpRequestResponse copyToTempFile() {
        throw new UnsupportedOperationException("Unimplemented method 'copyToTempFile'");
    }

    @Override
    public HttpRequestResponse withAnnotations(Annotations annotations) {
        return this;
    }

    @Override
    public HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers) {
        return this;
    }

    @Override
    public HttpRequestResponse withRequestMarkers(Marker... requestMarkers) {
        return this;
    }

    @Override
    public HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers) {
        return this;
    }

    @Override
    public HttpRequestResponse withResponseMarkers(Marker... responseMarkers) {
        return this;
    }

}