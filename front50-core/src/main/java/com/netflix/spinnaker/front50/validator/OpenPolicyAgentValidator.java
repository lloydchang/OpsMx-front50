/*
 * Copyright 2020 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.front50.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.netflix.spinnaker.front50.model.pipeline.Pipeline;
import com.netflix.spinnaker.front50.model.pipeline.PipelineDAO;
import com.netflix.spinnaker.kork.web.exceptions.ValidationException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;

@Component
public class OpenPolicyAgentValidator implements PipelineValidator {
  private static final Logger log = LoggerFactory.getLogger(OpenPolicyAgentValidator.class);
  private final PipelineDAO pipelineDAO;
  /* define configurable variables:
    opaUrl: OPA or OPA-Proxy base url
    opaResultKey: Not needed for Proxy. The key to watch in the return from OPA.
    policyLocation: Where in OPA is the policy located, generally this is v0/location/to/policy/path
                    And for Proxy it is /v1/staticPolicy/eval
    isOpaEnabled: Policy evaluation is skipped if this is false
    isOpaProxy : true if Proxy is present instead of OPA server.
  */
  @Value("${policy.opa.url:http://oes-server-svc.oes:8085}")
  private String opaUrl;

  @Value("${policy.opa.resultKey:deny}")
  private String opaResultKey;

  @Value("${policy.opa.policyLocation:/v1/staticPolicy/eval}")
  private String opaPolicyLocation;

  @Value("${policy.opa.enabled:false}")
  private boolean isOpaEnabled;

  @Value("${policy.opa.proxy:true}")
  private boolean isOpaProxy;

  @Value("${policy.opa.deltaVerification:false}")
  private boolean deltaVerification;

  private final Gson gson = new Gson();

  /* OPA spits JSON */
  private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
  private final OkHttpClient opaClient = new OkHttpClient();

  public OpenPolicyAgentValidator(PipelineDAO pipelineDAO) {
    this.pipelineDAO = pipelineDAO;
  }

  public void validate(Pipeline pipeline, Errors errors) {
    if (!isOpaEnabled) {
      return;
    }
    String finalInput = null;
    Response httpResponse;
    log.debug("OPA Server: {}", this.opaUrl);
    ObjectMapper objectMapper = new ObjectMapper();
    try {

      // Form input to opa
      finalInput = getOpaInput(pipeline, deltaVerification);

      log.debug("Verifying {} with OPA", finalInput);

      /* build our request to OPA */
      RequestBody requestBody = RequestBody.create(JSON, finalInput);
      String opaFinalUrl = String.format("%s/%s", this.opaUrl, this.opaPolicyLocation);
      String opaStringResponse;

      /* fetch the response from the spawned call execution */
      httpResponse = doPost(opaFinalUrl, requestBody);
      opaStringResponse = httpResponse.body().string();
      log.info("OPA response: {}", opaStringResponse);
      if (isOpaProxy) {
        if (httpResponse.code() != 200) {
          throw new ValidationException(opaStringResponse, null);
        }
      } else {
        JsonObject opaResponse = gson.fromJson(opaStringResponse, JsonObject.class);
        JsonObject opaResult;
        if (opaResponse.has("result")) {
          opaResult = opaResponse.get("result").getAsJsonObject();
          if (opaResult.has(opaResultKey)) {
            JsonArray resultKey = opaResult.get(opaResultKey).getAsJsonArray();
            if (resultKey.size() != 0) {
              throw new ValidationException(resultKey.get(0).getAsString(), null);
            }
          } else {
            throw new ValidationException(
                "There is no '" + opaResultKey + "' field in the OPA response", null);
          }
        } else {
          throw new ValidationException("There is no 'result' field in the OPA response", null);
        }
      }
    } catch (IOException e) {
      log.error("Communication exception for OPA at {}: {}", this.opaUrl, e.toString());
      throw new ValidationException(e.toString(), null);
    }
  }

  private String getOpaInput(Pipeline pipeline, boolean deltaVerification) {
    String application;
    String pipelineName;
    String finalInput = null;
    boolean initialSave = false;
    JsonObject newPipeline = pipelineToJsonObject(pipeline);
    if (newPipeline.has("application")) {
      application = newPipeline.get("application").getAsString();
      pipelineName = newPipeline.get("name").getAsString();
      log.debug("## input : {}", gson.toJson(newPipeline));
      if (newPipeline.has("stages")) {
        initialSave = newPipeline.get("stages").getAsJsonArray().size() == 0;
      }
      log.debug("## application : {}, pipelineName : {}", application, pipelineName);
      // if deltaVerification is true, add both current and new pipelines in single json
      if (deltaVerification && !initialSave) {
        List<Pipeline> pipelines =
            new ArrayList<>(pipelineDAO.getPipelinesByApplication(application, true));
        log.debug("## pipeline list count : {}", pipelines.size());
        Optional<Pipeline> currentPipeline =
            pipelines.stream()
                .filter(p -> ((String) p.get("name")).equalsIgnoreCase(pipelineName))
                .findFirst();
        if (currentPipeline.isPresent()) {
          finalInput = getFinalOpaInput(newPipeline, pipelineToJsonObject(currentPipeline.get()));
        } else {
          throw new ValidationException("There is no pipeline with name " + pipelineName, null);
        }
      } else {
        finalInput = gson.toJson(addWrapper(addWrapper(newPipeline, "new"), "input"));
      }
    } else {
      throw new ValidationException("The received pipeline doesn't have application field", null);
    }
    return finalInput;
  }

  private String getFinalOpaInput(JsonObject newPipeline, JsonObject currentPipeline) {
    JsonObject input = new JsonObject();
    input.add("new", newPipeline);
    input.add("current", currentPipeline);
    return gson.toJson(addWrapper(input, "input"));
  }

  private JsonObject addWrapper(JsonObject pipeline, String wrapper) {
    JsonObject input = new JsonObject();
    input.add(wrapper, pipeline);
    return input;
  }

  private JsonObject pipelineToJsonObject(Pipeline pipeline) {
    String pipelineStr = gson.toJson(pipeline, Pipeline.class);
    return gson.fromJson(pipelineStr, JsonObject.class);
  }

  private Response doGet(String url) throws IOException {
    Request req = (new Request.Builder()).url(url).get().build();
    return getResponse(url, req);
  }

  private Response doPost(String url, RequestBody requestBody) throws IOException {
    Request req = (new Request.Builder()).url(url).post(requestBody).build();
    return getResponse(url, req);
  }

  private Response getResponse(String url, Request req) throws IOException {
    Response httpResponse = this.opaClient.newCall(req).execute();
    ResponseBody responseBody = httpResponse.body();
    String opaStringResponse;
    if (responseBody == null) {
      throw new IOException("Http call yielded null response!! url:" + url);
    }
    return httpResponse;
  }
}