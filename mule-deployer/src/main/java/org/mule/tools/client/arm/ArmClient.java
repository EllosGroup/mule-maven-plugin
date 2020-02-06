/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.tools.client.arm;

import com.google.gson.GsonBuilder;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPart;
import org.glassfish.jersey.media.multipart.file.FileDataBodyPart;
import org.mule.tools.client.AbstractMuleClient;
import org.mule.tools.client.arm.model.*;
import org.mule.tools.client.core.exception.ClientException;
import org.mule.tools.client.core.exception.DeploymentException;
import org.mule.tools.client.model.TargetType;
import org.mule.tools.model.Deployment;
import org.mule.tools.model.anypoint.AnypointDeployment;
import org.mule.tools.model.anypoint.ArmDeployment;
import org.mule.tools.utils.DeployerLog;

import javax.net.ssl.*;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.io.File;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.mule.tools.client.arm.model.Component.*;

public class ArmClient extends AbstractMuleClient {

  public static final String HYBRID_API_V1 = "/hybrid/api/v1";

  private static final String CLUSTERS = HYBRID_API_V1 + "/clusters";
  private static final String APPLICATIONS = HYBRID_API_V1 + "/applications";
  private static final String SERVER_GROUPS = HYBRID_API_V1 + "/serverGroups";

  private static final String SERVERS = HYBRID_API_V1 + "/servers";
  private static final String REGISTRATION = HYBRID_API_V1 + "/servers/registrationToken";
  
  private static final String TARGETS = HYBRID_API_V1 + "/targets";
  private static final String COMPONENTS = "components";
  private static final String STARTED_STATUS = "STARTED";

  private boolean armInsecure;
  private boolean duplicateApplicationAllowed;

  public ArmClient(Deployment armDeployment, DeployerLog log) {
    super((AnypointDeployment) armDeployment, log);
    armInsecure = ((ArmDeployment) armDeployment).isArmInsecure();
    duplicateApplicationAllowed = ((ArmDeployment) armDeployment).isDuplicateApplicationAllowed();
    if (armInsecure) {
      log.warn("Using insecure mode for connecting to ARM, please consider configuring your truststore with ARM certificates. This option is insecure and not intended for production use.");
    }
  }

  public String getRegistrationToken() {
    RegistrationToken registrationToken = get(baseUri, REGISTRATION, RegistrationToken.class);
    return registrationToken.data;
  }

  public Boolean isStarted(int applicationId) {
    Application application = getApplication(applicationId);
    return STARTED_STATUS.equals(application.data.lastReportedStatus);
  }

  public Application getApplication(int applicationId) {
    return get(baseUri, APPLICATIONS + "/" + applicationId, Application.class);
  }

  public String undeployApplication(int applicationId) {
    Response response = delete(baseUri, APPLICATIONS + "/" + applicationId);
    checkResponseStatus(response);
    return response.readEntity(String.class);
  }

  public String undeployApplication(ApplicationMetadata applicationMetadata) {
    Integer applicationId = findApplicationId(applicationMetadata);
    if (applicationId == null) {
      throw new NotFoundException("The " + applicationMetadata.toString() + " does not exist.");
    }
    return undeployApplication(applicationId);
  }

  public Application deployApplication(ApplicationMetadata applicationMetadata) throws DeploymentException {
    validateApplicationState(applicationMetadata);
    MultiPart body = buildRequestBody(applicationMetadata);
    Response response = post(baseUri, APPLICATIONS, Entity.entity(body, body.getMediaType()));
    checkResponseStatus(response);
    Application application = response.readEntity(Application.class);
    enableAnalyticsAndTracking(applicationMetadata, application);
    return application;
  }
  
  public Application redeployApplication(int applicationId, ApplicationMetadata applicationMetadata) throws DeploymentException {
    validateApplicationState(applicationMetadata);
    MultiPart body = buildRequestBody(applicationMetadata);
    Response response = patch(baseUri, APPLICATIONS + "/" + applicationId, Entity.entity(body, body.getMediaType()));
    checkResponseStatus(response);
    Application application = response.readEntity(Application.class);
    enableAnalyticsAndTracking(applicationMetadata, application);
    return application;
  }

  private void validateApplicationState(ApplicationMetadata applicationMetadata) throws DeploymentException {
    Applications applications = getApplications();
    Data[] appsData = applications.data;
    if (appsData != null) {
      if (!duplicateApplicationAllowed) {
        for (int i = 0; i < appsData.length - 1; i++) {
          Data d = appsData[i];
          if ((d.desiredStatus.equals(STARTED_STATUS) || d.lastReportedStatus.equals(STARTED_STATUS))
                  && d.artifact.name.equals(applicationMetadata.getName())
                  && !d.target.name.equals(applicationMetadata.getTarget())) {
            String msg = String.format("Application %s is not allowed to be deployed to %s because it´s already running on %s. " +
                            "Please stop or delete the application on %s or change deploy target back to %s.",
                    applicationMetadata.getName(), applicationMetadata.getTarget(), d.target.name, d.target.name, d.target.name);
            log.error(msg);
            throw new DeploymentException(msg);
          }
        }
      }
    }
    log.info("Validate application state: OK");
  }

  protected void enableAnalyticsAndTracking(ApplicationMetadata applicationMetadata, Application app) {
    if (applicationMetadata.isEnableAnalytics() || applicationMetadata.isEnableTracking()) {
      String targetId = app.data.target.id;
      Components components = getComponents(targetId);
      // TODO: add support later to disable tracking agent
      if (applicationMetadata.isEnableAnalytics()) {
        Component component = findComponent(components, MULE_AGENT_TRACKING_HANDLER_ANALYTICS);
        log.debug("Analytics component(before): " + toJson(component));
        if (component != null) {
          EnableAnalytics ea = new EnableAnalytics();
          ea.enabled = true;
		  log.debug("Enable Analytics request: " + toJson(ea));
          Response response = patch(baseUri, TARGETS + "/" + targetId + "/" + COMPONENTS + "/" + component.component.id, ea);
          log.debug(String.format("Enable Analytics response: %s(%s) - %s", response.getStatusInfo(), response.getStatus(), response.readEntity(String.class)));
          checkResponseStatus(response);
          log.info("ARM analytics enabled!");
        }
		else {
          String errorMsg = "Analytics component could not be found!";
          log.error(errorMsg);
          throw new ClientException(errorMsg, -1, "");
		}
      }
      // TODO: add support later to remove tracking for specific app
      if (applicationMetadata.isEnableTracking()) {
        Component component = findComponent(components, MULE_AGENT_TRACKING_SERVICE);
        if (component != null) { 
          log.debug("Tracking component(before): " + toJson(component));
          String appName = app.data.artifact.name;
          Map<String,Object> config = component.configuration;
          List<Map<String, String>> trackedApplications;
          if (config == null) {
            config = new HashMap<>();
          }
          if (config.containsKey(TRACKED_APPLICATIONS)) {
            trackedApplications = (List<Map<String, String>>) config.get(TRACKED_APPLICATIONS);
          }
          else {
            trackedApplications = new ArrayList<>();
            config.put(TRACKED_APPLICATIONS, trackedApplications);
          }
          
          boolean found = false;
          for (Map<String, String> trackedApp : trackedApplications) {
            if (appName.equals(trackedApp.get("appName"))) { 
			  log.debug("Tracking component - app settings already exists, using " + toJson(trackedApp));
              found = true;
              break;
            }
          }
          if (!found) {
            Map<String,String> trackedApp = new HashMap<>();
            trackedApp.put("trackingLevel", "DEBUG");
            trackedApp.put("appName", appName);
            trackedApplications.add(trackedApp);
            log.debug("Tracking component - app settings not found, create new config " + toJson(trackedApp));
          }
          EnableTracking et = new EnableTracking();
          et.enabled = true;
          et.configuration = config;
          String json = toJson(et);
          log.debug("Enable Tracking request: " + json);
          Response response = patch(baseUri, TARGETS + "/" + targetId + "/" + COMPONENTS +"/" + component.component.id, json);
          log.debug(String.format("Enable Tracking response: %s(%s) - %s", response.getStatusInfo(), response.getStatus(), response.readEntity(String.class)));
          checkResponseStatus(response);
          log.info("ARM tracking enabled!");
        }
        else {
          String errorMsg = "Tracking component could not be found!";
          log.error(errorMsg);
          throw new ClientException(errorMsg, -1, "");
		}
      }
    }    
  }

  private MultiPart buildRequestBody(ApplicationMetadata metadata) {
    return buildRequestBody(metadata.getFile(), metadata.getName(), metadata.getTargetType(), metadata.getTarget(),
                            metadata.getProperties());
  }

  protected MultiPart buildRequestBody(File app, String appName, TargetType targetType, String target,
                                       Map<String, String> propertiesMap) {
    String id = getId(targetType, target);
    FileDataBodyPart applicationPart = createApplicationPart(app);
    FormDataMultiPart formDataMultiPart = new FormDataMultiPart()
        .field("artifactName", appName)
        .field("targetId", id);

    if (propertiesMap != null) {
      Map<String, Object> applicationPropertiesService = new HashMap<>();
      Map<String, Object> properties = new HashMap<>();
      properties.put("properties", propertiesMap);
      properties.put("applicationName", appName);
      applicationPropertiesService.put("mule.agent.application.properties.service", properties);
      formDataMultiPart.field("configuration",
                              new GsonBuilder().setPrettyPrinting().create().toJson(applicationPropertiesService));
    }

    return formDataMultiPart.bodyPart(applicationPart);
  }

  protected FileDataBodyPart createApplicationPart(File app) {
    return new FileDataBodyPart("file", app);
  }

  public String getId(TargetType targetType, String target) {
    String id = null;
    switch (targetType) {
      case server:
        id = findServerByName(target).id;
        break;
      case serverGroup:
        id = findServerGroupByName(target).id;
        break;
      case cluster:
        id = findClusterByName(target).id;
        break;
    }
    return id;
  }

  public Applications getApplications() {
    return get(baseUri, APPLICATIONS, Applications.class);
  }

  // TODO move servers and targets to another package due to the ugly ARM API
  public List<Target> getServers() {
    Targets targets = get(baseUri, SERVERS, Targets.class);
    return Arrays.asList(targets.data);
  }

  public Servers getServer(Integer serverId) {
    Servers target = get(baseUri, SERVERS + "/" + serverId, Servers.class);
    return target;
  }

  public void deleteServer(Integer serverId) {
    Response response = delete(baseUri, SERVERS + "/" + serverId);
    checkResponseStatus(response);
  }

  public Target findServerByName(String name) {
    return findTargetByName(name, SERVERS);
  }

  public Target findServerGroupByName(String name) {
    return findTargetByName(name, SERVER_GROUPS);
  }

  public Target findClusterByName(String name) {
    return findTargetByName(name, CLUSTERS);
  }

  private Target findTargetByName(String name, String path) {
    Targets response = get(baseUri, path, Targets.class);

    // Workaround because an empty array in the response is mapped as null
    if (response.data == null) {
      throw new RuntimeException("Couldn't find target named [" + name + "]");
    }

    for (int i = 0; i < response.data.length; i++) {
      if (name.equals(response.data[i].name)) {
        return response.data[i];
      }
    }
    throw new RuntimeException("Couldn't find target named [" + name + "]");
  }

  public Integer findApplicationId(ApplicationMetadata applicationMetadata) {
    Applications apps = getApplications();
    Data[] appArray = apps.data;
    if (appArray == null) {
      return null;
    }
    String targetId = getId(applicationMetadata.getTargetType(), applicationMetadata.getTarget());
    for (int i = 0; i < appArray.length; i++) {
      if (applicationMetadata.getName().equals(appArray[i].artifact.name) && targetId.equals(appArray[i].target.id)) {
        return appArray[i].id;
      }
    }
    return null;
  }
  
  public Components getComponents(String targetId) {
    String resJson = get(baseUri, TARGETS + "/" + targetId + "/" + COMPONENTS, String.class);
    Components components = fromJson(resJson, Components.class);
    return components;
  }
  
  public Component findComponent(Components components, String name) {
    Component[] compArray = components.data;
    for (int i = 0; i < compArray.length; i++) {
      if (name.equals(compArray[i].component.name)) {
        return compArray[i];
      }
    }
    return null;
  }
  
  protected void configureSecurityContext(ClientBuilder builder) {
    if (armInsecure) {
      try {
        SSLContext sslcontext = SSLContext.getInstance("TLS");
        sslcontext.init(null, new TrustManager[] {new TrustAllManager()}, new java.security.SecureRandom());
        builder.hostnameVerifier(new DummyHostnameVerifier()).sslContext(sslcontext);
      } catch (KeyManagementException | NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }

    }
  }

  private static class DummyHostnameVerifier implements HostnameVerifier {

    public boolean verify(String s, SSLSession sslSession) {
      return true;
    }
  }

  private static class TrustAllManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }

}
