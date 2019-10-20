package burp;

import io.swagger.client.model.BurpHttpService;

public class HttpService implements IHttpService {

    private BurpHttpService httpService;

    public HttpService(BurpHttpService httpService) {
        this.httpService = httpService;
    }

    @Override
    public String getHost() {
        return this.httpService.getHost();
    }

    @Override
    public int getPort() {
        return this.httpService.getPort();
    }

    @Override
    public String getProtocol() {
        return this.httpService.getScheme();
    }
    
}