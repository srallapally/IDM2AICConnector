@Grab(group='org.apache.httpcomponents', module='httpclient', version='4.5.13')
@Grab(group='commons-io', module='commons-io', version='2.11.0')
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClients
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.groovy.ScriptedConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.filter.Filter

def operation = operation as OperationType
def configuration = configuration as ScriptedConfiguration
def log = log as Log


return true

