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
import java.util.UUID;

/**
 * ExecuteBurpMenuResult
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2019-10-20T09:30:08.127-04:00")
public class ExecuteBurpMenuResult {
  @SerializedName("Success")
  private Boolean success = null;

  @SerializedName("ErrorMessage")
  private String errorMessage = null;

  @SerializedName("ScanID")
  private UUID scanID = null;

  @SerializedName("ResultIds")
  private List<BurpNotification> resultIds = null;

  public ExecuteBurpMenuResult success(Boolean success) {
    this.success = success;
    return this;
  }

   /**
   * Get success
   * @return success
  **/
  @ApiModelProperty(value = "")
  public Boolean isSuccess() {
    return success;
  }

  public void setSuccess(Boolean success) {
    this.success = success;
  }

  public ExecuteBurpMenuResult errorMessage(String errorMessage) {
    this.errorMessage = errorMessage;
    return this;
  }

   /**
   * Get errorMessage
   * @return errorMessage
  **/
  @ApiModelProperty(value = "")
  public String getErrorMessage() {
    return errorMessage;
  }

  public void setErrorMessage(String errorMessage) {
    this.errorMessage = errorMessage;
  }

  public ExecuteBurpMenuResult scanID(UUID scanID) {
    this.scanID = scanID;
    return this;
  }

   /**
   * Get scanID
   * @return scanID
  **/
  @ApiModelProperty(value = "")
  public UUID getScanID() {
    return scanID;
  }

  public void setScanID(UUID scanID) {
    this.scanID = scanID;
  }

  public ExecuteBurpMenuResult resultIds(List<BurpNotification> resultIds) {
    this.resultIds = resultIds;
    return this;
  }

  public ExecuteBurpMenuResult addResultIdsItem(BurpNotification resultIdsItem) {
    if (this.resultIds == null) {
      this.resultIds = new ArrayList<BurpNotification>();
    }
    this.resultIds.add(resultIdsItem);
    return this;
  }

   /**
   * Get resultIds
   * @return resultIds
  **/
  @ApiModelProperty(value = "")
  public List<BurpNotification> getResultIds() {
    return resultIds;
  }

  public void setResultIds(List<BurpNotification> resultIds) {
    this.resultIds = resultIds;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ExecuteBurpMenuResult executeBurpMenuResult = (ExecuteBurpMenuResult) o;
    return Objects.equals(this.success, executeBurpMenuResult.success) &&
        Objects.equals(this.errorMessage, executeBurpMenuResult.errorMessage) &&
        Objects.equals(this.scanID, executeBurpMenuResult.scanID) &&
        Objects.equals(this.resultIds, executeBurpMenuResult.resultIds);
  }

  @Override
  public int hashCode() {
    return Objects.hash(success, errorMessage, scanID, resultIds);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ExecuteBurpMenuResult {\n");
    
    sb.append("    success: ").append(toIndentedString(success)).append("\n");
    sb.append("    errorMessage: ").append(toIndentedString(errorMessage)).append("\n");
    sb.append("    scanID: ").append(toIndentedString(scanID)).append("\n");
    sb.append("    resultIds: ").append(toIndentedString(resultIds)).append("\n");
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

