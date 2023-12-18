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
 import io.swagger.annotations.ApiModel;
 import io.swagger.annotations.ApiModelProperty;
 
 /**
  * 
  */
 @ApiModel(description = "")
 @javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2023-03-05T11:32:31.617-05:00")
 public class BurpIssueInfiltratorEvent {
   @SerializedName("ParameterName")
   private String parameterName = null;
 
   @SerializedName("Platform")
   private String platform = null;
 
   @SerializedName("Signature")
   private String signature = null;
 
   @SerializedName("StackTrace")
   private String stackTrace = null;
 
   @SerializedName("ParameterValue")
   private String parameterValue = null;
 
   @SerializedName("CollaboratorEvent")
   private String collaboratorEvent = null;
 
   public BurpIssueInfiltratorEvent parameterName(String parameterName) {
     this.parameterName = parameterName;
     return this;
   }
 
    /**
    * Get parameterName
    * @return parameterName
   **/
   @ApiModelProperty(value = "")
   public String getParameterName() {
     return parameterName;
   }
 
   public void setParameterName(String parameterName) {
     this.parameterName = parameterName;
   }
 
   public BurpIssueInfiltratorEvent platform(String platform) {
     this.platform = platform;
     return this;
   }
 
    /**
    * Get platform
    * @return platform
   **/
   @ApiModelProperty(value = "")
   public String getPlatform() {
     return platform;
   }
 
   public void setPlatform(String platform) {
     this.platform = platform;
   }
 
   public BurpIssueInfiltratorEvent signature(String signature) {
     this.signature = signature;
     return this;
   }
 
    /**
    * Get signature
    * @return signature
   **/
   @ApiModelProperty(value = "")
   public String getSignature() {
     return signature;
   }
 
   public void setSignature(String signature) {
     this.signature = signature;
   }
 
   public BurpIssueInfiltratorEvent stackTrace(String stackTrace) {
     this.stackTrace = stackTrace;
     return this;
   }
 
    /**
    * Get stackTrace
    * @return stackTrace
   **/
   @ApiModelProperty(value = "")
   public String getStackTrace() {
     return stackTrace;
   }
 
   public void setStackTrace(String stackTrace) {
     this.stackTrace = stackTrace;
   }
 
   public BurpIssueInfiltratorEvent parameterValue(String parameterValue) {
     this.parameterValue = parameterValue;
     return this;
   }
 
    /**
    * Get parameterValue
    * @return parameterValue
   **/
   @ApiModelProperty(value = "")
   public String getParameterValue() {
     return parameterValue;
   }
 
   public void setParameterValue(String parameterValue) {
     this.parameterValue = parameterValue;
   }
 
   public BurpIssueInfiltratorEvent collaboratorEvent(String collaboratorEvent) {
     this.collaboratorEvent = collaboratorEvent;
     return this;
   }
 
    /**
    * Get collaboratorEvent
    * @return collaboratorEvent
   **/
   @ApiModelProperty(value = "")
   public String getCollaboratorEvent() {
     return collaboratorEvent;
   }
 
   public void setCollaboratorEvent(String collaboratorEvent) {
     this.collaboratorEvent = collaboratorEvent;
   }
 
 
   @Override
   public boolean equals(java.lang.Object o) {
     if (this == o) {
       return true;
     }
     if (o == null || getClass() != o.getClass()) {
       return false;
     }
     BurpIssueInfiltratorEvent burpIssueInfiltratorEvent = (BurpIssueInfiltratorEvent) o;
     return Objects.equals(this.parameterName, burpIssueInfiltratorEvent.parameterName) &&
         Objects.equals(this.platform, burpIssueInfiltratorEvent.platform) &&
         Objects.equals(this.signature, burpIssueInfiltratorEvent.signature) &&
         Objects.equals(this.stackTrace, burpIssueInfiltratorEvent.stackTrace) &&
         Objects.equals(this.parameterValue, burpIssueInfiltratorEvent.parameterValue) &&
         Objects.equals(this.collaboratorEvent, burpIssueInfiltratorEvent.collaboratorEvent);
   }
 
   @Override
   public int hashCode() {
     return Objects.hash(parameterName, platform, signature, stackTrace, parameterValue, collaboratorEvent);
   }
 
 
   @Override
   public String toString() {
     StringBuilder sb = new StringBuilder();
     sb.append("class BurpIssueInfiltratorEvent {\n");
     
     sb.append("    parameterName: ").append(toIndentedString(parameterName)).append("\n");
     sb.append("    platform: ").append(toIndentedString(platform)).append("\n");
     sb.append("    signature: ").append(toIndentedString(signature)).append("\n");
     sb.append("    stackTrace: ").append(toIndentedString(stackTrace)).append("\n");
     sb.append("    parameterValue: ").append(toIndentedString(parameterValue)).append("\n");
     sb.append("    collaboratorEvent: ").append(toIndentedString(collaboratorEvent)).append("\n");
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
 
 