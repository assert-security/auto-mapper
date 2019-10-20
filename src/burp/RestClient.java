package burp;

import java.io.PrintWriter;
import java.util.List;
import java.util.UUID;

import io.swagger.client.ApiException;
import io.swagger.client.api.BurpApi;
import io.swagger.client.model.BurpIssue;
import io.swagger.client.model.BurpMenu;
import io.swagger.client.model.BurpNotifications;
import io.swagger.client.model.BurpTraffic;
import io.swagger.client.model.ExecuteBurpMenuResult;
import io.swagger.client.model.OperationResultData;

public class RestClient {

  private final BurpApi burpApi = new BurpApi();

  public RestClient(PrintWriter outputWriter) {
    burpApi.getApiClient().setBasePath("http://localhost:9001");
  }

  public String createBurpSession(String token) throws ApiException {
    String ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.createBurpSession();
    return ret;
  }

  public OperationResultData closeBurpSession(String token, String sessionID) throws ApiException {
    OperationResultData ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.closeBurpSession(sessionID);
    return ret;
  }

  public List<BurpMenu> getBurpMenus(String token, String sessionID) throws ApiException {
    List<BurpMenu> ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.getBurpMenus(sessionID);
    return ret;
  }

  public ExecuteBurpMenuResult executeBurpMenu(String token, String sessionID, BurpMenu menu) throws ApiException {
    ExecuteBurpMenuResult ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.executeBurpMenu(sessionID, menu);
    return ret;
  }

  public BurpNotifications getBurpNotifications(String token, String sessionID) throws ApiException {
    BurpNotifications ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.getBurpNotifications(sessionID);
    return ret;
  }

  public List<BurpTraffic> getBurpTraffic(String token, String sessionID, Long id, UUID scanID) throws ApiException {
    List<BurpTraffic> ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.getBurpTraffic(sessionID, id, scanID);
    return ret;
  }

  public BurpIssue getBurpIssue(String token, String sessionID, Long id, String applicationName, UUID scanID) throws ApiException {
    BurpIssue ret = null;
    burpApi.getApiClient().addDefaultHeader("X-Meta-Venari", token);
    ret = burpApi.getBurpIssue(sessionID, id, applicationName, scanID);
    return ret;
  }

}