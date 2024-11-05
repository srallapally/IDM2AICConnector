@Grab(group='org.apache.httpcomponents', module='httpclient', version='4.5.13')
@Grab(group='commons-io', module='commons-io', version='2.11.0')
import org.apache.http.client.methods.HttpDelete
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.groovy.ScriptedConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions

def operation = operation as OperationType
def configuration = configuration as ScriptedConfiguration

def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def log = log as Log

CLIENT_ID = configuration.propertyBag.AIC.x_client_id
CLIENT_SECRET = configuration.propertyBag.AIC.x_client_secret
BASE_URL = configuration.propertyBag.AIC.x_base_url
TOKEN_URL = "${BASE_URL}/am/oauth2/alpha/access_token"

println "########## Entering " + operation + " Script"

switch(objectClass){
    case ObjectClass.ACCOUNT:
        println "Deleting Account for " + objectClass + ": " + uid.uidValue + " Account"
        def httpClient = HttpClients.createDefault()
        def path = "${BASE_URL}/openidm/managed/alpha_user/" + uid.uidValue
        def accessToken = null
        accessToken = generateToken()
        if(accessToken == null)
            throw new ConnectorException("Unable to obtain an access token") as java.lang.Throwable
        try {
            // Create POST request
            def httpDelete = new HttpDelete(path)
            // Set headers
            httpPost.setHeader('Accept', 'application/json')
            httpPost.setHeader('Content-Type', 'application/json')
            httpPost.setHeader('Authorization', "Bearer ${accessToken}")
            // Execute request
            def response = httpClient.execute(httpDelete)
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

    case ObjectClass.GROUP:
        throw new ConnectorException("Deleting object of type: " + objectClass.objectClassValue + " is not supported")
            
}

            