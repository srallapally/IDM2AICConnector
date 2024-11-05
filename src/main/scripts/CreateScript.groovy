
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.groovy.ScriptedConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributesAccessor
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.Uid
import org.identityconnectors.framework.common.exceptions.ConnectorException

def operation = operation as OperationType
def configuration = configuration as ScriptedConfiguration

def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def createAttributes = new AttributesAccessor(attributes as Set<Attribute>)
def uid = id as String
def log = log as Log

switch (operation) {
    case OperationType.CREATE:
        println "Entering update script for " + objectClass
        switch (objectClass) {
            case ObjectClass.ACCOUNT:
                def fileLocation = configuration.propertyBag.__ACCOUNT__.fileloc
                def userName = null
                def firstName = null
                def lastName = null

                if (createAttributes.hasAttribute("userName")) {
                    userName = createAttributes.findString("userName")
                }
       }
        return new Uid(userName)
}