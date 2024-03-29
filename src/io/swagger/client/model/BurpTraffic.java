/*
 * LocalServer
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: v1
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package io.swagger.client.model;

import java.util.Objects;
import com.google.gson.annotations.SerializedName;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;

/**
 * BurpTraffic
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2019-10-20T09:30:08.127-04:00")
public class BurpTraffic {
  @SerializedName("SessionID")
  private String sessionID = null;

  @SerializedName("HttpService")
  private BurpHttpService httpService = null;

  @SerializedName("Base64RequestBytes")
  private String base64RequestBytes = null;

  @SerializedName("Base64ResponseBytes")
  private String base64ResponseBytes = null;

  @SerializedName("RequestMatches")
  private List<MatchPosition> requestMatches = null;

  @SerializedName("ResponseMatches")
  private List<MatchPosition> responseMatches = null;

  public BurpTraffic sessionID(String sessionID) {
    this.sessionID = sessionID;
    return this;
  }

   /**
   * Get sessionID
   * @return sessionID
  **/
  @ApiModelProperty(value = "")
  public String getSessionID() {
    return sessionID;
  }

  public void setSessionID(String sessionID) {
    this.sessionID = sessionID;
  }

  public BurpTraffic httpService(BurpHttpService httpService) {
    this.httpService = httpService;
    return this;
  }

   /**
   * Get httpService
   * @return httpService
  **/
  @ApiModelProperty(value = "")
  public BurpHttpService getHttpService() {
    return httpService;
  }

  public void setHttpService(BurpHttpService httpService) {
    this.httpService = httpService;
  }

  public BurpTraffic base64RequestBytes(String base64RequestBytes) {
    this.base64RequestBytes = base64RequestBytes;
    return this;
  }

   /**
   * Get base64RequestBytes
   * @return base64RequestBytes
  **/
  @ApiModelProperty(value = "")
  public String getBase64RequestBytes() {
    return base64RequestBytes;
  }

  public void setBase64RequestBytes(String base64RequestBytes) {
    this.base64RequestBytes = base64RequestBytes;
  }

  public BurpTraffic base64ResponseBytes(String base64ResponseBytes) {
    this.base64ResponseBytes = base64ResponseBytes;
    return this;
  }

   /**
   * Get base64ResponseBytes
   * @return base64ResponseBytes
  **/
  @ApiModelProperty(value = "")
  public String getBase64ResponseBytes() {
    return base64ResponseBytes;
  }

  public void setBase64ResponseBytes(String base64ResponseBytes) {
    this.base64ResponseBytes = base64ResponseBytes;
  }

  public BurpTraffic requestMatches(List<MatchPosition> requestMatches) {
    this.requestMatches = requestMatches;
    return this;
  }

  public BurpTraffic addRequestMatchesItem(MatchPosition requestMatchesItem) {
    if (this.requestMatches == null) {
      this.requestMatches = new ArrayList<MatchPosition>();
    }
    this.requestMatches.add(requestMatchesItem);
    return this;
  }

   /**
   * Get requestMatches
   * @return requestMatches
  **/
  @ApiModelProperty(value = "")
  public List<MatchPosition> getRequestMatches() {
    return requestMatches;
  }

  public void setRequestMatches(List<MatchPosition> requestMatches) {
    this.requestMatches = requestMatches;
  }

  public BurpTraffic responseMatches(List<MatchPosition> responseMatches) {
    this.responseMatches = responseMatches;
    return this;
  }

  public BurpTraffic addResponseMatchesItem(MatchPosition responseMatchesItem) {
    if (this.responseMatches == null) {
      this.responseMatches = new ArrayList<MatchPosition>();
    }
    this.responseMatches.add(responseMatchesItem);
    return this;
  }

   /**
   * Get responseMatches
   * @return responseMatches
  **/
  @ApiModelProperty(value = "")
  public List<MatchPosition> getResponseMatches() {
    return responseMatches;
  }

  public void setResponseMatches(List<MatchPosition> responseMatches) {
    this.responseMatches = responseMatches;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    BurpTraffic burpTraffic = (BurpTraffic) o;
    return Objects.equals(this.sessionID, burpTraffic.sessionID) &&
        Objects.equals(this.httpService, burpTraffic.httpService) &&
        Objects.equals(this.base64RequestBytes, burpTraffic.base64RequestBytes) &&
        Objects.equals(this.base64ResponseBytes, burpTraffic.base64ResponseBytes) &&
        Objects.equals(this.requestMatches, burpTraffic.requestMatches) &&
        Objects.equals(this.responseMatches, burpTraffic.responseMatches);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sessionID, httpService, base64RequestBytes, base64ResponseBytes, requestMatches, responseMatches);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BurpTraffic {\n");
    
    sb.append("    sessionID: ").append(toIndentedString(sessionID)).append("\n");
    sb.append("    httpService: ").append(toIndentedString(httpService)).append("\n");
    sb.append("    base64RequestBytes: ").append(toIndentedString(base64RequestBytes)).append("\n");
    sb.append("    base64ResponseBytes: ").append(toIndentedString(base64ResponseBytes)).append("\n");
    sb.append("    requestMatches: ").append(toIndentedString(requestMatches)).append("\n");
    sb.append("    responseMatches: ").append(toIndentedString(responseMatches)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

