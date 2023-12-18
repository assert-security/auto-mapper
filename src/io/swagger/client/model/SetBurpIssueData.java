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
 import java.util.ArrayList;
 import java.util.List;
 
 /**
  * 
  */
 @ApiModel(description = "")
 @javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2023-03-05T11:32:31.617-05:00")
 public class SetBurpIssueData {
   @SerializedName("SessionID")
   private String sessionID = null;
 
   @SerializedName("Issues")
   private List<BurpIssueData> issues = null;
 
   public SetBurpIssueData sessionID(String sessionID) {
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
 
   public SetBurpIssueData issues(List<BurpIssueData> issues) {
     this.issues = issues;
     return this;
   }
 
   public SetBurpIssueData addIssuesItem(BurpIssueData issuesItem) {
     if (this.issues == null) {
       this.issues = new ArrayList<BurpIssueData>();
     }
     this.issues.add(issuesItem);
     return this;
   }
 
    /**
    * Get issues
    * @return issues
   **/
   @ApiModelProperty(value = "")
   public List<BurpIssueData> getIssues() {
     return issues;
   }
 
   public void setIssues(List<BurpIssueData> issues) {
     this.issues = issues;
   }
 
 
   @Override
   public boolean equals(java.lang.Object o) {
     if (this == o) {
       return true;
     }
     if (o == null || getClass() != o.getClass()) {
       return false;
     }
     SetBurpIssueData setBurpIssueData = (SetBurpIssueData) o;
     return Objects.equals(this.sessionID, setBurpIssueData.sessionID) &&
         Objects.equals(this.issues, setBurpIssueData.issues);
   }
 
   @Override
   public int hashCode() {
     return Objects.hash(sessionID, issues);
   }
 
 
   @Override
   public String toString() {
     StringBuilder sb = new StringBuilder();
     sb.append("class SetBurpIssueData {\n");
     
     sb.append("    sessionID: ").append(toIndentedString(sessionID)).append("\n");
     sb.append("    issues: ").append(toIndentedString(issues)).append("\n");
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
 
 