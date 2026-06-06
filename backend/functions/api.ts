import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { User, requirePermission } from './rbac';
import * as crypto from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface TableConfig {
  name: string;
  pkField: string;
  skField?: string;
  gsiFields?: string[];
}

const TABLES: Record<string, TableConfig> = {
  '0': { name: 'users', pkField: 'userId' },
  '1': { name: 'products', pkField: 'productId' },
  '2': { name: 'productSpecs', pkField: 'productSpecId' },
  '3': { name: 'processes', pkField: 'processId' },
  '4': { name: 'productionLines', pkField: 'lineId' },
  '5': { name: 'materials', pkField: 'materialId' },
  '6': { name: 'productionPlans', pkField: 'productionPlanId' },
  '7': { name: 'productionOrders', pkField: 'productionOrderId' },
  '8': { name: 'workResults', pkField: 'workResultId' },
  '9': { name: 'qualityStandards', pkField: 'qualityStandardId' },
  '10': { name: 'qualityInspectionResults', pkField: 'inspectionResultId' },
  '11': { name: 'standardProcedures', pkField: 'procedureId' },
  '12': { name: 'progressManagement', pkField: 'progressId' },
  '13': { name: 'anomalyDetectionLogs', pkField: 'anomalyDetectionId' },
  '14': { name: 'alertNotificationHistory', pkField: 'alertNotificationHistoryId' },
  '15': { name: 'workHistory', pkField: 'workHistoryId' },
  '16': { name: 'processHandoverInfo', pkField: 'handoverId' }
};

function getUser(event: APIGatewayProxyEvent): User {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  if (!authHeader) {
    throw new Error('No authorization header');
  }
  
  // Simple mock user extraction - in real implementation, decode JWT
  const role = authHeader.includes('admin') ? 'admin' : 
               authHeader.includes('operator') ? 'operator' : 'viewer';
  
  return {
    id: 'user-' + crypto.randomUUID(),
    role
  };
}

function createResponse(statusCode: number, body: any): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    },
    body: JSON.stringify(body)
  };
}

async function createAuditLog(action: string, resource: string, userId: string, details?: any): Promise<void> {
  const auditItem = {
    pk: 'AUDIT',
    sk: `${Date.now()}-${crypto.randomUUID()}`,
    action,
    resource,
    userId,
    timestamp: new Date().toISOString(),
    details: details || {}
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditItem
  }));
}

function validateRequired(item: any, requiredFields: string[]): string[] {
  const errors: string[] = [];
  for (const field of requiredFields) {
    if (!item[field]) {
      errors.push(`${field} is required`);
    }
  }
  return errors;
}

function getRequiredFields(tableIndex: string): string[] {
  const fieldMap: Record<string, string[]> = {
    '0': ['userId', 'username', 'passwordHash', 'fullName', 'permissionLevel', 'activeFlag', 'createdAt', 'updatedAt', 'createdBy'],
    '1': ['productId', 'productCode', 'productName', 'productCategory', 'unit', 'activeFlag', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy'],
    '2': ['productSpecId', 'productId', 'specVersion', 'specName', 'activeFlag', 'createdAt', 'updatedAt', 'createdBy'],
    '3': ['processId', 'processCode', 'processName', 'processCategory', 'activeFlag', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy'],
    '4': ['lineId', 'lineCode', 'lineName', 'factoryCode', 'operationStatus', 'activeFlag', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy'],
    '5': ['materialId', 'materialCode', 'materialName', 'materialCategory', 'unit', 'activeFlag', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy'],
    '6': ['productionPlanId', 'planNumber', 'productId', 'productionLineId', 'plannedQuantity', 'plannedStartDateTime', 'plannedEndDateTime', 'priority', 'planStatus', 'createdBy', 'createdAt', 'updatedAt'],
    '7': ['productionOrderId', 'productionOrderNumber', 'productionPlanId', 'productId', 'productionLineId', 'productionQuantity', 'priority', 'plannedStartDateTime', 'plannedEndDateTime', 'status', 'createdBy', 'createdAt'],
    '8': ['workResultId', 'productionOrderId', 'processId', 'productionLineId', 'workerId', 'workStartDateTime', 'plannedQuantity', 'actualQuantity', 'goodQuantity', 'defectQuantity', 'workStatus', 'createdAt', 'updatedAt', 'createdBy'],
    '9': ['qualityStandardId', 'standardName', 'inspectionItem', 'requiredFlag', 'validStartDate', 'createdAt', 'updatedAt', 'createdBy'],
    '10': ['inspectionResultId', 'productionOrderId', 'productId', 'qualityStandardId', 'inspectionProcessId', 'inspectionDateTime', 'inspectorId', 'inspectionLotNumber', 'inspectionQuantity', 'passQuantity', 'failQuantity', 'overallJudgment', 'createdAt', 'updatedAt', 'createdBy'],
    '11': ['procedureId', 'procedureCode', 'procedureName', 'productId', 'processId', 'version', 'workContent', 'standardWorkTime', 'activeFlag', 'createdBy', 'createdAt', 'updatedBy', 'updatedAt'],
    '12': ['progressId', 'productionOrderId', 'processId', 'productionLineId', 'plannedStartDateTime', 'plannedEndDateTime', 'progressRate', 'plannedQuantity', 'completedQuantity', 'processStatus', 'delayFlag', 'createdAt', 'updatedAt', 'updatedBy'],
    '13': ['anomalyDetectionId', 'productionLineId', 'processId', 'anomalyType', 'anomalyContent', 'detectionMethod', 'severity', 'detectionDateTime', 'responseStatus', 'createdAt', 'updatedAt', 'createdBy'],
    '14': ['alertNotificationHistoryId', 'anomalyDetectionLogId', 'notificationTargetUserId', 'notificationMethod', 'notificationStatus', 'notificationSentDateTime', 'alertSeverity', 'notificationContent', 'createdAt', 'updatedAt'],
    '15': ['workHistoryId', 'productionOrderId', 'processId', 'productionLineId', 'workerId', 'workStartDateTime', 'workStatus', 'createdAt', 'updatedAt', 'createdBy'],
    '16': ['handoverId', 'productionOrderId', 'handoverSourceProcessId', 'handoverTargetProcessId', 'productionLineId', 'lotNumber', 'processedQuantity', 'qualityStatus', 'abnormalityFlag', 'handoverDateTime', 'handoverUserId', 'handoverStatus', 'createdAt', 'updatedAt', 'createdBy']
  };
  return fieldMap[tableIndex] || [];
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return createResponse(200, {});
    }

    const user = getUser(event);
    const path = event.path;
    const method = event.httpMethod;
    
    // Handle /resources endpoint
    if (path === '/resources' && method === 'GET') {
      requirePermission(user, 'resources', 'read');
      
      const resources = Object.entries(TABLES).map(([index, config]) => ({
        index,
        name: config.name,
        pkField: config.pkField,
        skField: config.skField,
        gsiFields: config.gsiFields
      }));
      
      return createResponse(200, { resources });
    }
    
    // Parse table index from path
    const pathMatch = path.match(/^\/api\/(\d+)(?:\/(.+))?$/);
    if (!pathMatch) {
      return createResponse(404, { error: 'Invalid path' });
    }
    
    const tableIndex = pathMatch[1];
    const subPath = pathMatch[2];
    const tableConfig = TABLES[tableIndex];
    
    if (!tableConfig) {
      return createResponse(404, { error: 'Table not found' });
    }
    
    const pk = `${tableConfig.name.toUpperCase()}`;
    
    // Handle bulk import
    if (subPath === 'bulk' && method === 'POST') {
      requirePermission(user, tableConfig.name, 'bulk');
      
      const body = JSON.parse(event.body || '{}');
      const items = body.items || [];
      
      if (!Array.isArray(items)) {
        return createResponse(400, { error: 'Items must be an array' });
      }
      
      let imported = 0;
      let failed = 0;
      const errors: string[] = [];
      
      // Process in batches of 25 (DynamoDB limit)
      for (let i = 0; i < items.length; i += 25) {
        const batch = items.slice(i, i + 25);
        const writeRequests = [];
        
        for (const item of batch) {
          try {
            const requiredFields = getRequiredFields(tableIndex);
            const validationErrors = validateRequired(item, requiredFields.filter(f => !['createdAt', 'updatedAt', 'createdBy', 'updatedBy'].includes(f)));
            
            if (validationErrors.length > 0) {
              errors.push(`Item validation failed: ${validationErrors.join(', ')}`);
              failed++;
              continue;
            }
            
            const now = new Date().toISOString();
            const enrichedItem = {
              ...item,
              pk,
              sk: item[tableConfig.pkField] || crypto.randomUUID(),
              [tableConfig.pkField]: item[tableConfig.pkField] || crypto.randomUUID(),
              createdAt: now,
              updatedAt: now,
              createdBy: user.id
            };
            
            writeRequests.push({
              PutRequest: {
                Item: enrichedItem
              }
            });
          } catch (error) {
            errors.push(`Item processing failed: ${error}`);
            failed++;
          }
        }
        
        if (writeRequests.length > 0) {
          try {
            await docClient.send(new BatchWriteCommand({
              RequestItems: {
                [TABLE_NAME]: writeRequests
              }
            }));
            imported += writeRequests.length;
          } catch (error) {
            errors.push(`Batch write failed: ${error}`);
            failed += writeRequests.length;
          }
        }
      }
      
      await createAuditLog('BULK_IMPORT', tableConfig.name, user.id, { imported, failed });
      
      return createResponse(200, { imported, failed, errors });
    }
    
    // Handle CRUD operations
    switch (method) {
      case 'GET':
        requirePermission(user, tableConfig.name, 'read');
        
        if (subPath) {
          // Get single item
          const result = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: { pk, sk: subPath }
          }));
          
          if (!result.Item) {
            return createResponse(404, { error: 'Item not found' });
          }
          
          return createResponse(200, result.Item);
        } else {
          // List items
          const result = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: 'pk = :pk',
            ExpressionAttributeValues: {
              ':pk': pk
            }
          }));
          
          return createResponse(200, { items: result.Items || [] });
        }
        
      case 'POST':
        requirePermission(user, tableConfig.name, 'create');
        
        const createBody = JSON.parse(event.body || '{}');
        const requiredFields = getRequiredFields(tableIndex);
        const createValidationErrors = validateRequired(createBody, requiredFields.filter(f => !['createdAt', 'updatedAt', 'createdBy', 'updatedBy'].includes(f)));
        
        if (createValidationErrors.length > 0) {
          return createResponse(400, { errors: createValidationErrors });
        }
        
        const now = new Date().toISOString();
        const newItem = {
          ...createBody,
          pk,
          sk: createBody[tableConfig.pkField] || crypto.randomUUID(),
          [tableConfig.pkField]: createBody[tableConfig.pkField] || crypto.randomUUID(),
          createdAt: now,
          updatedAt: now,
          createdBy: user.id,
          updatedBy: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: newItem
        }));
        
        await createAuditLog('CREATE', tableConfig.name, user.id, { itemId: newItem.sk });
        
        return createResponse(201, newItem);
        
      case 'PUT':
        requirePermission(user, tableConfig.name, 'update');
        
        if (!subPath) {
          return createResponse(400, { error: 'Item ID required for update' });
        }
        
        const updateBody = JSON.parse(event.body || '{}');
        const updateRequiredFields = getRequiredFields(tableIndex);
        const updateValidationErrors = validateRequired(updateBody, updateRequiredFields.filter(f => !['createdAt', 'updatedAt', 'createdBy', 'updatedBy'].includes(f)));
        
        if (updateValidationErrors.length > 0) {
          return createResponse(400, { errors: updateValidationErrors });
        }
        
        const updatedItem = {
          ...updateBody,
          pk,
          sk: subPath,
          [tableConfig.pkField]: subPath,
          updatedAt: new Date().toISOString(),
          updatedBy: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: updatedItem
        }));
        
        await createAuditLog('UPDATE', tableConfig.name, user.id, { itemId: subPath });
        
        return createResponse(200, updatedItem);
        
      case 'DELETE':
        requirePermission(user, tableConfig.name, 'delete');
        
        if (!subPath) {
          return createResponse(400, { error: 'Item ID required for delete' });
        }
        
        await docClient.send(new DeleteCommand({
          TableName: TABLE_NAME,
          Key: { pk, sk: subPath }
        }));
        
        await createAuditLog('DELETE', tableConfig.name, user.id, { itemId: subPath });
        
        return createResponse(200, { message: 'Item deleted successfully' });
        
      default:
        return createResponse(405, { error: 'Method not allowed' });
    }
    
  } catch (error: any) {
    console.error('Error:', error);
    
    if (error.message.includes('Insufficient permissions')) {
      return createResponse(403, { error: 'Forbidden' });
    }
    
    if (error.message.includes('No authorization header')) {
      return createResponse(401, { error: 'Unauthorized' });
    }
    
    return createResponse(500, { error: 'Internal server error' });
  }
};