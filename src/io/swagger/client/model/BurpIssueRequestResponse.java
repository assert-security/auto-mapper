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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import io.swagger.client.model.BurpIssueRequest;
import io.swagger.client.model.BurpIssueResponse;
import java.io.IOException;

/**
 * 
 */
@ApiModel(description = "")
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2023-03-05T11:32:31.617-05:00")
public class BurpIssueRequestResponse {
    @SerializedName("HttpService")
    private BurpHttpService httpService = null;

      @SerializedName("Request")
    private BurpIssueRequest request = null;

    @SerializedName("Response")
    private BurpIssueResponse response = null;

    @SerializedName("RequestMarkers")
    private List<MatchPosition> requestMarkers = null;

    @SerializedName("ResponseMarkers")
    private List<MatchPosition> responseMarkers = null;

    @SerializedName("IsResponseRedirected")
    private Boolean isResponseRedirected = null;

    public BurpIssueRequestResponse httpService(BurpHttpService httpService) {
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
    
    public BurpIssueRequestResponse request(BurpIssueRequest request) {
        this.request = request;
        return this;
    }

    /**
     * Get request
     * 
     * @return request
     **/
    @ApiModelProperty(value = "")
    public BurpIssueRequest getRequest() {
        return request;
    }

    public void setRequest(BurpIssueRequest request) {
        this.request = request;
    }

    public BurpIssueRequestResponse response(BurpIssueResponse response) {
        this.response = response;
        return this;
    }

    /**
     * Get response
     * 
     * @return response
     **/
    @ApiModelProperty(value = "")
    public BurpIssueResponse getResponse() {
        return response;
    }

    public void setResponse(BurpIssueResponse response) {
        this.response = response;
    }

    public BurpIssueRequestResponse requestMarkers(List<MatchPosition> requestMarkers) {
        this.requestMarkers = requestMarkers;
        return this;
    }

    public BurpIssueRequestResponse addRequestMarkersItem(MatchPosition requestMarkersItem) {
        if (this.requestMarkers == null) {
            this.requestMarkers = new ArrayList<MatchPosition>();
        }
        this.requestMarkers.add(requestMarkersItem);
        return this;
    }

    /**
     * Get requestMarkers
     * 
     * @return requestMarkers
     **/
    @ApiModelProperty(value = "")
    public List<MatchPosition> getRequestMarkers() {
        return requestMarkers;
    }

    public void setRequestMarkers(List<MatchPosition> requestMarkers) {
        this.requestMarkers = requestMarkers;
    }

    public BurpIssueRequestResponse responseMarkers(List<MatchPosition> responseMarkers) {
        this.responseMarkers = responseMarkers;
        return this;
    }

    public BurpIssueRequestResponse addResponseMarkersItem(MatchPosition responseMarkersItem) {
        if (this.responseMarkers == null) {
            this.responseMarkers = new ArrayList<MatchPosition>();
        }
        this.responseMarkers.add(responseMarkersItem);
        return this;
    }

    /**
     * Get responseMarkers
     * 
     * @return responseMarkers
     **/
    @ApiModelProperty(value = "")
    public List<MatchPosition> getResponseMarkers() {
        return responseMarkers;
    }

    public void setResponseMarkers(List<MatchPosition> responseMarkers) {
        this.responseMarkers = responseMarkers;
    }

    public BurpIssueRequestResponse isResponseRedirected(Boolean isResponseRedirected) {
        this.isResponseRedirected = isResponseRedirected;
        return this;
    }

    /**
     * Get isResponseRedirected
     * 
     * @return isResponseRedirected
     **/
    @ApiModelProperty(value = "")
    public Boolean isIsResponseRedirected() {
        return isResponseRedirected;
    }

    public void setIsResponseRedirected(Boolean isResponseRedirected) {
        this.isResponseRedirected = isResponseRedirected;
    }

    @Override
    public boolean equals(java.lang.Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        BurpIssueRequestResponse burpIssueRequestResponse = (BurpIssueRequestResponse) o;
        return Objects.equals(this.request, burpIssueRequestResponse.request) &&
                Objects.equals(this.response, burpIssueRequestResponse.response) &&
                Objects.equals(this.isResponseRedirected, burpIssueRequestResponse.isResponseRedirected);
    }

    @Override
    public int hashCode() {
        return Objects.hash(request, response, isResponseRedirected);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class BurpIssueRequestResponse {\n");

        sb.append("    request: ").append(toIndentedString(request)).append("\n");
        sb.append("    response: ").append(toIndentedString(response)).append("\n");
        sb.append("    isResponseRedirected: ").append(toIndentedString(isResponseRedirected)).append("\n");
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
