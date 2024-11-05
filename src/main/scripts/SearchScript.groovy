@Grab(group='org.apache.httpcomponents', module='httpclient', version='4.5.13')
@Grab(group='commons-io', module='commons-io', version='2.11.0')

import groovy.json.JsonSlurper
import org.apache.commons.codec.binary.Base64
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.HttpClients
import org.apache.http.message.BasicNameValuePair
import org.apache.http.util.EntityUtils
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.groovy.ScriptedConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.filter.EqualsFilter
import org.identityconnectors.framework.common.objects.filter.Filter
import org.identityconnectors.framework.common.objects.filter.OrFilter

def operation = operation as OperationType
def configuration = configuration as ScriptedConfiguration
def filter = filter as Filter
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def pageSize = 10
def currentPagedResultsCookie = null

def resultCount = 0

CLIENT_ID = configuration.propertyBag.AIC.x_client_id
CLIENT_SECRET = configuration.propertyBag.AIC.x_client_secret
BASE_URL = configuration.propertyBag.AIC.x_base_url
TOKEN_URL = "${BASE_URL}/am/oauth2/alpha/access_token"


println "########## Entering " + operation + " Script"
println "########## ObjectClass: " + objectClass.objectClassValue
def query = [:]
def queryFilter = 'true'
def get = false
def or = false

switch (objectClass) {
    case objectClass.ACCOUNT:
        def index = -1
        def path = "${BASE_URL}/openidm/managed/alpha_user?"
        if(filter != null){
            def username = null
            if (filter instanceof EqualsFilter){
                    println "#### EqualsFilter ####"
                    def attrName = ((EqualsFilter) filter).getAttribute()
                    println "attrName: " + attrName.getName()
                    def attrValue = ((EqualsFilter) filter).getAttribute().getValue().get(0).toString()
                    if (attrName.is(Name.NAME)) {
                        path = path + "_queryFilter=userName%20eq%20%22"+attrValue+"%22"

                    } else if (attrName.is(Uid.NAME)){
                        path = path + "_queryFilter=_id%20eq%20%22"+attrValue+"%22"
                    } else {
                        path = path + "_queryFilter=" + attrName.getName()+"%20eq%20%22"+attrValue+"%22"

                    }
                    path = path + "&_fields=*,effectiveRoles"
                    println "Handling for Source Query " + path
                    def resources = null
                    def accessToken = null
                    accessToken = generateToken()
                    if(accessToken == null)
                        throw new ConnectorException("Unable to obtain an access token")

                    def response = getResponse(path,accessToken)

                    response.result.each { item ->
                            def roleList = []
                            def effectiveRoles = []
                            effectiveRoles = item.effectiveRoles
                            if(effectiveRoles == null || effectiveRoles.size() == 0) {
                               println " No Roles for "+item.userName
                            } else {
                                println " Getting user's role memberships for "+item.userName                      
                                effectiveRoles.each { role ->
                                    roleList.add(role._refResourceId)
                                }
                            }
                            handler {
                                uid item.userName
                                id item.userName
                                attribute 'userName', item.userName
                                attribute 'givenName', item.givenName
                                attribute 'sn', item.sn
                                attribute 'mail', item.mail
                                attribute 'roles', roleList
                            }
                    }
            } else if (filter instanceof OrFilter){
                println "#### OrFilter ####"
                def keys = getOrFilters((OrFilter)filter)
                // println "#### keys ####" + keys
                def s = null
                keys.each { key ->
                    if(s) {
                            s = s + "or%20userName%20eq%20%22"+key+"%22%20"
                    } else {
                            s = "userName%20eq%20%22"+key+"%22%20"
                    }    
                }
                path = path + "_queryFilter="+s+"&_fields=*,effectiveRoles"
                println "OrFilter:Query String: " + path 
                def resources = null
                def accessToken = null
                accessToken = generateToken()
                if(accessToken == null)
                    throw new ConnectorException("Unable to obtain an access token")

                def response = getResponse(path,accessToken)
                response.result.each { item ->
                    def roleList = []
                    def effectiveRoles = []
                    effectiveRoles = item.effectiveRoles
                    if(effectiveRoles == null || effectiveRoles.size() == 0) {
                        println " No Roles for "+item.userName
                    } else {
                        println " Getting user's role memberships for "+item.userName                      
                        effectiveRoles.each { role ->
                            roleList.add(role._refResourceId)
                        }
                    }

                    handler {
                         uid item.userName
                        id item.userName
                        attribute 'userName', item.userName
                        attribute 'givenName', item.givenName    
                        attribute 'sn', item.sn
                        attribute 'mail', item.mail
                        attribute 'roles', roleList
                    }
                }
            } else {
                print "#### Filter #### " + filter + " is not supported" 
            }
            return new SearchResult()
        }
        if (null != options.pageSize) {
            pageSize = options.pageSize
            println "########## pageSize: " + pageSize
            path = path + "_queryFilter=true&_fields=*,effectiveRoles&_pageSize="+pageSize
            
            //path = path + "_queryFilter=true&_pageSize="+pageSize
            if (null != options.pagedResultsOffset) {
               offset = options.pagedResultsOffset
               path = path + "&_pagedResultsOffset="+offset
            } else if (null != options.pagedResultsCookie) {
                currentPagedResultsCookie = options.pagedResultsCookie.toString()
                path = path + "&_pagedResultsCookie="+currentPagedResultsCookie
            }
      
            println "Query String: " + path
            def resources = null
            def accessToken = null
            accessToken = generateToken()
            if(accessToken == null)
                throw new ConnectorException("Unable to obtain an access token")

            def response = getResponse(path,accessToken)
            if(response) {
                response.result.each { item ->
                    def roleList = []
                    def effectiveRoles = []
                effectiveRoles = item.effectiveRoles
                if(effectiveRoles == null || effectiveRoles.size() == 0) {
                    println " No Roles for "+item.userName
                } else {
                    println " Getting user's role memberships for "+item.userName                      
                    effectiveRoles.each { role ->
                            roleList.add(role._refResourceId)
                    }
                }
                    //roleList = getUserRoleIds(item.userName)
                    handler {
                        uid item._id
                        id item.userName
                        attribute 'userName', item.userName
                        attribute 'givenName', item.givenName    
                        attribute 'sn', item.sn
                        attribute 'mail', item.mail
                        attribute 'accountStatus', item.accountStatus
                        attribute 'roles', roleList
                }
            }
           }
            /*
            if(count == pageSize) {
                String newCookie = response.json.pagedResultsOffset.toString() + count
                return new SearchResult(newCookie, -1) 
            } else if(count < pageSize) {
                return new SearchResult() 
            }
             */
            return new SearchResult()
        } else {
              println "Page Size is not set"
              //println "RECON: Query String: " + path
              def offset = 0
              userPath =  "/managed/user?_queryFilter=true&_fields=*,effectiveRoles"
              boolean doContinue = true
             // while(doContinue) {
              println "Enter RECON:Query String: " + userPath
              def resources = null
              def accessToken = null
              accessToken = generateToken()
              if(accessToken == null)
                throw new ConnectorException("Unable to obtain an access token")

              def response = null
              response = getResponse(path,accessToken)
              if(!response)
                  throw new ConnectorException("Search failure")
                //println "RECON: Response: " + response.json
                 def count = 0
                 currentPagedResultsCookie = response.json.pagedResultsCookie.toString()
                 response.result.each { item ->
                            def roleList = []
                            def effectiveRoles = []
                            effectiveRoles = item.effectiveRoles
                            if(effectiveRoles == null || effectiveRoles.size() == 0) {
                               println " No Roles for "+item.userName
                            } else {
                                println " Getting user's role memberships for "+item.userName                      
                                effectiveRoles.each { role ->
                                    roleList.add(role._refResourceId)
                                }
                            }
                            handler {
                                uid item.userName
                                id item.userName
                                attribute 'userName', item.userName
                                attribute 'givenName', item.givenName
                                attribute 'sn', item.sn
                                attribute 'mail', item.mail
                                attribute 'roles', roleList
                            }
                 }
                 return new SearchResult()
        }       
    break
    case objectClass.GROUP:
        def path = "${BASE_URL}/openidm/managed/alpha_role?_sortKeys=name&field=*"
        println " Group Path: "+path
        query.each {key, value ->
            if(value){
                path = path + "&"+key+"="+value
            }
        }
        path = path + "&_totalPagedResultsPolicy=ESTIMATE"
        if(filter != null){
            def rolename = null
            if (filter instanceof EqualsFilter){
                //println "#### EqualsFilter ####"
                def attrName = ((EqualsFilter) filter).getAttribute()
                println "attrName: " + attrName
                if (attrName.is(Name.NAME)) {
                    rolename = ((EqualsFilter) filter).getAttribute().getValue().get(0)
                    rolename = java.net.URLEncoder.encode(rolename, "UTF-8") 
                    path = path + "&_queryFilter=name%20eq%20%22"+rolename+"%22"
                } else if(attrName.is(Uid.NAME)){
                    rolename = ((EqualsFilter) filter).getAttribute().getValue().get(0)
                    rolename = java.net.URLEncoder.encode(rolename, "UTF-8") 
                    path = path + "&_queryFilter=_id%20eq%20%22"+rolename+"%22"
                }
                get = true
            } else if (filter instanceof OrFilter){
                /*
                //println "#### OrFilter ####"
                def keys = getOrFilters((OrFilter)filter)
               // println "#### keys ####" + keys
                def s = null
                keys.each { key ->
                    if(s) {
                        s = s + "or%20nameame%20eq%20%22"+key+"%22%20"
                    } else {
                         s = "name%20eq%20%22"+key+"%22%20"
                    }    
                }
                path = path + "&_queryFilter=roletype%20eq%20%22Entitlement%22%20and%20%28"+s+"%29"
                get = false
                 */
            }
        }
        else {
            path = path + "&_queryFilter=true"
        }        
        println "Group Query String: " + path
        def resources = null
        def index = -1
        def accessToken = null
        accessToken = generateToken()
        if(accessToken == null)
            throw new ConnectorException("Unable to obtain an access token")

        def response = getResponse(path,accessToken)
        response.result.each { item ->
                handler {
                  uid item._id
                  id item.name
                  attribute 'roleName', item.name
                  attribute 'roleDescription', item.description
               }
        }
        return new SearchResult()
    default:
        break
}

def getOrFilters(OrFilter filter) {
    def ids = []
    Filter left = filter.getLeft()
    Filter right = filter.getRight()
    if(left instanceof EqualsFilter) {
        String id = ((EqualsFilter)left).getAttribute().getValue().get(0).toString()
        ids.add(id)
    } else if(left instanceof OrFilter) {
        ids.addAll(getOrFilters((OrFilter)left))
    }
    if(right instanceof EqualsFilter) {
        String id = ((EqualsFilter)right).getAttribute().getValue().get(0).toString()
        ids.add(id)
    } else if(right instanceof OrFilter) {
        ids.addAll(getOrFilters((OrFilter)right))
    }
    return ids

}
def getUserId(String userName){
    def path = "${BASE_URL}/managed/user?_sortKeys=userName&_fields=*" + "&_queryFilter=userName+eq+%22" + userName + "%22"
    def accessToken = null
    accessToken = generateToken()
    if(accessToken == null)
        throw new ConnectorException("Unable to obtain an access token")

    def response = getResponse(path,accessToken)
    def roleList = []
    def userid = null
    response.json.result.each { item ->
        userid = item._id
    }
    println "userid: " + userid
    return userid
}

def getUserRoleIds(String userName){
    def roleIds = []
    def userid = null
    println " Getting user "+userName+" user id"
    userid = getUserId(userName)
    if(userid) {
        def path = "${BASE_URL}/managed/user/"+userid+"/roles?_queryFilter=true&_fields=_ref/*,name"
        println "getUserRoleIds:"+path
        def accessToken = null
        accessToken = generateToken()
        if(accessToken == null)
            throw new ConnectorException("Unable to obtain an access token")

        def response = getResponse(path,accessToken)
    
        response.json.result.each { item ->
        //println "Adding "+item._id + " with name " + item.name
         roleIds.add(item._refResourceId)
        }
        return roleIds
    } else {
        println "User not found "+userName
        return null
    }
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