@Grab(group='org.apache.httpcomponents', module='httpclient', version='4.5.13')
@Grab(group='commons-io', module='commons-io', version='2.11.0')

import groovy.json.JsonSlurper
import org.apache.commons.codec.binary.Base64
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpPatch
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClients
import org.apache.http.message.BasicNameValuePair
import org.apache.http.util.EntityUtils
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.groovy.ScriptedConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.*

def operation = operation as OperationType
def configuration = configuration as ScriptedConfiguration

def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def updateAttributes = new AttributesAccessor(attributes as Set<Attribute>)
def uid = uid as Uid
def log = log as Log
patchOperations = []


CLIENT_ID = configuration.propertyBag.AIC.x_client_id
CLIENT_SECRET = configuration.propertyBag.AIC.x_client_secret
BASE_URL = configuration.propertyBag.AIC.x_base_url
TOKEN_URL = "${BASE_URL}/am/oauth2/alpha/access_token"

println "Entering " + operation + " Script"
println "ObjectClass: " + objectClass.objectClassValue


switch(objectClass){
    case ObjectClass.ACCOUNT:
        println "Updating Account for " + objectClass + ": " + uid.uidValue + " Account"

        def currentRoles = []

        def path = "${BASE_URL}/openidm/managed/alpha_user?_action=patch&_queryFilter=_id+eq+%22" + uid.uidValue + "%22"

        def accessToken = null
        accessToken = generateToken()
        if(accessToken == null)
            throw new ConnectorException("Unable to obtain an access token") as java.lang.Throwable

        // Build the patch payload
        addReplace("userName",  updateAttributes.findString("userName"))
        addReplace("givenName", updateAttributes.findString("givenName"))
        addReplace("sn", updateAttributes.findString("sn"))
        addReplace("mail",updateAttributes.findString("mail"))
        // Function to make the REST call

        def patchResponse = makePostRestCall(patchOperations,path,accessToken)
        if (patchResponse > 200)
            throw new ConnectorException("Update failed ") as java.lang.Throwable

        if (updateAttributes.hasAttribute("roles")) {
            currentRoles = updateAttributes.findList("roles")
            log.ok(" Final Roles: " + currentRoles + "for " + uid.uidValue)
            // To get current role memberships from IDM, we need the user id
            def userid = getUserId(uid.uidValue)
            def userRoles = []
            userRoles = getUserRoles(uid.uidValue)
            log.ok("Roles in IDM: " + userRoles)
            // Roles to be revoked
            if(userRoles.size() > 0){
                userRoles.each {item ->
                    if(!currentRoles.contains(item)){
                        log.ok("Revoking role: " + item)
                        revokeRoleFromUser(userid,item as String)
                    }
                }
            }
            // Roles to be added
            if(currentRoles.size() > 0){
                currentRoles.each {item ->
                    if(!userRoles.contains(item)){
                        log.ok("Adding role: " + item)
                        addRoleToUser(userid,item as String)
                    }
                }
            }
        }
        return uid
    case ObjectClass.GROUP:
        /**
         * We aren't doing anything with groups in this example
         */
        println "Entering update script for " + objectClass + " with attributes: " + updateAttributes + " Group"
        def groupName = null
        def groupDescription = null

        if (updateAttributes.hasAttribute("roleName")) {
            groupName = updateAttributes.findString("roleName")
        }

        if (updateAttributes.hasAttribute("roleDescription")) {
            groupDescription = updateAttributes.findString("roleDescription")
        }
        return groupName
    default:
        println "UpdateScript can not handle object type: " + objectClass.objectClassValue
        throw new ConnectorException("UpdateScript can not handle object type: " + objectClass.objectClassValue)
}

def addRoleToUser(String userId,String roleId){
    def roleGrantUrl = "${BASE_URL}/openidm/managed/user/"+userId
    def grantString = "[{\"operation\": \"add\",\"field\": \"/roles/-\",\"value\": {\"_ref\" : \"managed/alpha_role/"+roleId+"\"}}]"
    println "This is my grant string: " + grantString
    def accessToken = null
    accessToken = generateToken()
    if(accessToken == null)
        throw new ConnectorException("Unable to obtain an access token")
    def patchResponse = null
    patchResponse = makePatchRestCall(roleGrantUrl, accessToken, grantString)
}

def revokeRoleFromUser(String userId, String roleId){
    def path = "${BASE_URL}/openidm/managed/alpha_user/"+userId+"/alpha_roles?_queryFilter=_refResourceId%20eq%20%22"+roleId+"%22&_fields=_ref/*,name"
    def accessToken = null
    accessToken = generateToken()
    if(accessToken == null)
        throw new ConnectorException("Unable to obtain an access token")

    def roleResponse = makeGetRestCall(path,accessToken)

    def id = roleResponse.result[0]._id
    def refResId = roleResponse..result[0]._refResourceId
    def rev = roleResponse..result[0]._rev
    def ref = roleResponse..result[0]._ref
    def refResourceRev = roleResponse.result[0]._refResourceRev
    def revokeString = "[ { \"operation\":  \"remove\", \"field\": \"/roles\", " +
            "\"value\": { \"_ref\": \""+ref+"\"," +
            " \"_refResourceCollection\":  \"managed/role\", " +
            " \"_refResourceId\": \""+ refResId+"\", " +
            " \"_refProperties\":  { " +
            "\"_id\": \"" + id +"\", " +
            "\"_rev\": \""+ rev +"\" } } }]";
    println "This is my revoke string: " + revokeString
    def roleDeleteStr = "${BASE_URL}/openidm/managed/user/"+userId
    def response = null
    response = makePatchRestCall(revokeString,roleDeleteStr, accessToken)
}

// Helper functions
def addReplace(String field, String value) {
    if (value != null) {
        // Remove leading slash if present and validate field
        def normalizedField = field.startsWith('/') ? field.substring(1) : field

        patchOperations << [
                operation: 'replace',
                field: "/${normalizedField}",
                value: value
        ]
    }
}

def makeGetRestCall(String url, String accessToken){
    def response = getResponse(url,accessToken)
    println "Response : " + response
    return response
}

def makePostRestCall(List payload, String url, String accessToken) {
    def httpClient = HttpClients.createDefault()
    try {
        // Create POST request
        def httpPost = new HttpPost(url)
        // Set headers
        httpPost.setHeader('Accept', 'application/json')
        httpPost.setHeader('Content-Type', 'application/json')
        httpPost.setHeader('Authorization', "Bearer ${accessToken}")

        // Set payload
        def jsonPayload = groovy.json.JsonOutput.toJson(payload)
        println "Calling update on ${url}"
        println "Update payload:\n${jsonPayload}"
        httpPost.setEntity(new StringEntity(jsonPayload))
        // Execute request
        def response = httpClient.execute(httpPost)
        try {
            def statusCode = response.statusLine.statusCode
            def responseBody = EntityUtils.toString(response.entity)
            if (responseBody) {
                println groovy.json.JsonOutput.prettyPrint(responseBody)
            }
            return statusCode
        } finally {
            response.close()
        }
    } finally {
        httpClient.close()
    }
}

def makePatchRestCall(String payload, String url, String accessToken) {
    def httpClient = HttpClients.createDefault()
    try {
        // Create PATCH request
        def httpPatch = new HttpPatch(url)
        // Set headers
        httpPatch.setHeader('Accept', 'application/json')
        httpPatch.setHeader('Content-Type', 'application/json')
        httpPatch.setHeader('Authorization', "Bearer ${accessToken}")

        // Set payload
        def jsonPayload = groovy.json.JsonOutput.toJson(payload)
        println "Calling update on ${url}"
        println "Update payload:\n${jsonPayload}"
        httpPost.setEntity(new StringEntity(jsonPayload))
        // Execute request
        def response = httpClient.execute(httpPatch)
        try {
            def statusCode = response.statusLine.statusCode
            def responseBody = EntityUtils.toString(response.entity)
            if (responseBody) {
                println groovy.json.JsonOutput.prettyPrint(responseBody)
            }
            return statusCode
        } finally {
            response.close()
        }
    } finally {
        httpClient.close()
    }
}

def getUser(String userName){
    def path = "${BASE_URL}/managed/alpha_user?_sortKeys=userName&_fields=*" + "&_queryFilter=userName+eq+%22" + userName + "%22"
    def accessToken = null
    accessToken = generateToken()
    if(accessToken == null)
        throw new ConnectorException("Unable to obtain an access token")

    def response = getResponse(path,accessToken)
    println "User : " + response
    return response
}

def getUserId(String userName){
    def path = "${BASE_URL}/managed/alpha_user?_sortKeys=userName&_fields=*" + "&_queryFilter=userName+eq+%22" + userName + "%22"
    def accessToken = null
    accessToken = generateToken()
    if(accessToken == null)
        throw new ConnectorException("Unable to obtain an access token")

    def response = getResponse(path,accessToken)
    def roleList = []
    def userid = null
    response.result.each { item ->
        userid = item._id
    }
    println "userid: " + userid
    return userid
}

def getUserRoles(String userid){
    def path = "${BASE_URL}/managed/alpha_user?_sortKeys=userName&_fields=*" + "&_queryFilter=userName+eq+%22" + userid + "%22"
    def accessToken = generateToken()
    if(accessToken == null)
        throw new ConnectorException("Unable to obtain an access token")

    def response = getResponse(path,accessToken)
    def roleList = []
    response.result.each { item ->
        item.effectiveRoles.each { role ->
            roleList.add(role._refResourceId)
        }
    }
    if(roleList.size() == 0){
        println "No roles found for user: " + userid
    }
    return roleList

}

def getResponse(String url, String accessToken){
    // Create HTTP client
    def httpClient = HttpClients.createDefault()
    // Create GET request
    def httpGet = new HttpGet(url)
    // Add authorization header
    println "Access Token:${accessToken}"
    httpGet.addHeader('Authorization', "Bearer ${accessToken}")

    // Execute request
    def response = httpClient.execute(httpGet)

    try {
        // Get response body
        def responseBody = EntityUtils.toString(response.entity)

        // Parse JSON response
        def jsonSlurper = new JsonSlurper()
        def parsedJson = jsonSlurper.parseText(responseBody)
        //println "JSON Text:${parsedJson}"
        return parsedJson
    } catch (Exception e) {
        println "Error occurred: ${e.message}"
        e.printStackTrace()
    } finally {
        // Close HTTP client
        httpClient.close()
    }
    return null
}
def generateToken() {
    def httpClient = HttpClients.createDefault()
    try {
        // Create POST request
        def httpPost = new HttpPost(TOKEN_URL)

        // Add Authorization header
        String auth = "${CLIENT_ID}:${CLIENT_SECRET}"
        String encodedAuth = Base64.encodeBase64String(auth.getBytes())
        httpPost.addHeader('Authorization', "Basic ${encodedAuth}")

        // Add form parameters
        def params = [
                new BasicNameValuePair('grant_type', 'client_credentials'),
                new BasicNameValuePair('scope', 'fr:idm:* fr:iga:*')
        ]
        httpPost.entity = new UrlEncodedFormEntity(params)

        // Execute request
        def response = httpClient.execute(httpPost)
        try {
            def statusCode = response.statusLine.statusCode
            def responseBody = EntityUtils.toString(response.entity)

            if (statusCode == 200) {
                def jsonSlurper = new JsonSlurper()
                def jsonResponse = jsonSlurper.parseText(responseBody)
                def accessToken = jsonResponse.access_token
                println "Successfully retrieved access token"
                return accessToken
            } else {
                println "Failed to retrieve access token. Status code: ${statusCode}"
                println "Response: ${responseBody}"
                return null
            }
        } finally {
            response.close()
        }
    } finally {
        httpClient.close()
    }
}