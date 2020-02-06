/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.tools.client.arm.model;

import java.util.Map;

public class Component {
  public static final String TRACKED_APPLICATIONS = "trackedApplications";
  public static final String MULE_AGENT_TRACKING_SERVICE = "mule.agent.tracking.service";
  public static final String MULE_AGENT_TRACKING_HANDLER_ANALYTICS = "mule.agent.tracking.handler.analytics";
  
  public ComponentInfo component;
  public boolean enabled;
  public Map<String, Object> configuration;
}
