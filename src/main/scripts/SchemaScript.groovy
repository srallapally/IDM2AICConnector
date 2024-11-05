import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.groovy.ScriptedConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptionInfoBuilder
import org.identityconnectors.framework.spi.operations.SearchOp

import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.MULTIVALUED
import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.REQUIRED

def operation = operation as OperationType
def configuration = configuration as ScriptedConfiguration
def log = log as Log

return builder.schema({
    objectClass {
        type ObjectClass.ACCOUNT_NAME
        attributes {
            userName String.class, REQUIRED
            sn String.class, REQUIRED
            mail String.class, REQUIRED
            accountStatus String.class, REQUIRED
            givenName String.class, REQUIRED
            middleName String.class
            description String.class
            roles String.class, MULTIVALUED
        }

    }
    objectClass {
        type ObjectClass.GROUP_NAME
        attributes {
            roleName String.class, REQUIRED
            roleDescription String.class
        }
    }

    defineOperationOption OperationOptionInfoBuilder.buildPagedResultsCookie(), SearchOp
    defineOperationOption OperationOptionInfoBuilder.buildPagedResultsOffset(), SearchOp
    defineOperationOption OperationOptionInfoBuilder.buildPageSize(), SearchOp
    defineOperationOption OperationOptionInfoBuilder.buildSortKeys(), SearchOp
    defineOperationOption OperationOptionInfoBuilder.buildRunWithUser()
    defineOperationOption OperationOptionInfoBuilder.buildRunWithPassword()
    }
)

