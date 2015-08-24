/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.approval;

import java.util.Calendar;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.cloudfoundry.identity.uaa.util.json.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.util.json.JsonDateSerializer;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Approval {

    private String userId;

    private String clientId;

    private String scope;

    public enum ApprovalStatus {
        APPROVED,
        DENIED
    }

    private ApprovalStatus status;

    public ApprovalStatus getStatus() {
        return status;
    }

    private Date expiresAt;

    private Date lastUpdatedAt;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId == null ? "" : userId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId == null ? "" : clientId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope == null ? "" : scope;
    }

    @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
    public Date getExpiresAt() {
        return expiresAt;
    }

    @JsonDeserialize(using = JsonDateDeserializer.class)
    public void setExpiresAt(Date expiresAt) {
        if (expiresAt == null) {
            Calendar thirtyMinFromNow = Calendar.getInstance();
            thirtyMinFromNow.add(Calendar.MINUTE, 30);
            expiresAt = thirtyMinFromNow.getTime();
        }
        this.expiresAt = expiresAt;
    }

    @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
    public Date getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    @JsonDeserialize(using = JsonDateDeserializer.class)
    public void setLastUpdatedAt(Date lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }

    @JsonIgnore
    public boolean isCurrentlyActive() {
        return expiresAt != null && expiresAt.after(new Date());
    }

    public Approval(String userId, String clientId, String scope, int expiresIn, ApprovalStatus status) {
        this(userId, clientId, scope, new Date(), status, new Date());
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, expiresIn);
        setExpiresAt(expiresAt.getTime());
    }

    public Approval(String userId, String clientId, String scope, Date expiresAt, ApprovalStatus status) {
        this(userId, clientId, scope, expiresAt, status, new Date());
    }

    public Approval(String userId, String clientId, String scope, Date expiresAt, ApprovalStatus status,
                    Date lastUpdatedAt) {
        this.userId = userId;
        this.clientId = clientId;
        this.scope = scope;
        this.expiresAt = expiresAt;
        this.status = status;
        this.lastUpdatedAt = lastUpdatedAt;
    }

    public Approval() {
    }

    public Approval(Approval approval) {
        this(approval.getUserId(),
            approval.getClientId(),
            approval.getScope(),
            approval.getExpiresAt(),
            approval.getStatus(),
            approval.getLastUpdatedAt()
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Approval approval = (Approval) o;

        if (getUserId() != null ? !getUserId().equals(approval.getUserId()) : approval.getUserId() != null)
            return false;
        if (getClientId() != null ? !getClientId().equals(approval.getClientId()) : approval.getClientId() != null)
            return false;
        if (getScope() != null ? !getScope().equals(approval.getScope()) : approval.getScope() != null) return false;
        return getStatus() == approval.getStatus();

    }

    @Override
    public int hashCode() {
        int result = getUserId() != null ? getUserId().hashCode() : 0;
        result = 31 * result + (getClientId() != null ? getClientId().hashCode() : 0);
        result = 31 * result + (getScope() != null ? getScope().hashCode() : 0);
        result = 31 * result + (getStatus() != null ? getStatus().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return String.format("[%s, %s, %s, %s, %s, %s]", userId, scope, clientId, expiresAt, status.toString(),
                        lastUpdatedAt);
    }

    public void setStatus(ApprovalStatus status) {
        this.status = status;
    }

}
