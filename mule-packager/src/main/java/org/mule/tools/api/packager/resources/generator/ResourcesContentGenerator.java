/*
 * Mule ESB Maven Tools
 * <p>
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * <p>
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */

package org.mule.tools.api.packager.resources.generator;

import org.mule.tools.api.packager.resources.content.ResourcesContent;

/**
 * Generates the resources of a mule package, resolving the resources locations.
 */
public interface ResourcesContentGenerator {

  ResourcesContent generate();
}