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

/**
 * OperationResultData
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2019-10-02T15:49:06.974-04:00")
public class OperationResultData {
  @SerializedName("Succeeded")
  private Boolean succeeded = null;

  @SerializedName("Message")
  private String message = null;

  public OperationResultData succeeded(Boolean succeeded) {
    this.succeeded = succeeded;
    return this;
  }

   /**
   * Get succeeded
   * @return succeeded
  **/
  @ApiModelProperty(value = "")
  public Boolean isSucceeded() {
    return succeeded;
  }

  public void setSucceeded(Boolean succeeded) {
    this.succeeded = succeeded;
  }

  public OperationResultData message(String message) {
    this.message = message;
    return this;
  }

   /**
   * Get message
   * @return message
  **/
  @ApiModelProperty(value = "")
  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    OperationResultData operationResultData = (OperationResultData) o;
    return Objects.equals(this.succeeded, operationResultData.succeeded) &&
        Objects.equals(this.message, operationResultData.message);
  }

  @Override
  public int hashCode() {
    return Objects.hash(succeeded, message);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class OperationResultData {\n");
    
    sb.append("    succeeded: ").append(toIndentedString(succeeded)).append("\n");
    sb.append("    message: ").append(toIndentedString(message)).append("\n");
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

