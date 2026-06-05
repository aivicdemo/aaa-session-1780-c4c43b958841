import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { hasPermission, createUser, PERMISSIONS } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'production-management';

interface ResourceConfig {
  entityType: string;
  readPermission: string;
  writePermission: string;
  deletePermission: string;
  idField: string;
}

const RESOURCE_CONFIGS: Record<string, ResourceConfig> = {
  '0': { entityType: 'USER', readPermission: PERMISSIONS.READ_USERS, writePermission: PERMISSIONS.WRITE_USERS, deletePermission: PERMISSIONS.DELETE_USERS, idField: 'userId' },
  '1': { entityType: 'PRODUCT', readPermission: PERMISSIONS.READ_PRODUCTS, writePermission: PERMISSIONS.WRITE_PRODUCTS, deletePermission: PERMISSIONS.DELETE_PRODUCTS, idField: 'productId' },
  '2': { entityType: 'SPECIFICATION', readPermission: PERMISSIONS.READ_SPECIFICATIONS, writePermission: PERMISSIONS.WRITE_SPECIFICATIONS, deletePermission: PERMISSIONS.DELETE_SPECIFICATIONS, idField: 'specificationId' },
  '3': { entityType: 'PROCESS', readPermission: PERMISSIONS.READ_PROCESSES, writePermission: PERMISSIONS.WRITE_PROCESSES, deletePermission: PERMISSIONS.DELETE_PROCESSES, idField: 'processId' },
  '4': { entityType: 'LINE', readPermission: PERMISSIONS.READ_LINES, writePermission: PERMISSIONS.WRITE_LINES, deletePermission: PERMISSIONS.DELETE_LINES, idField: 'lineId' },
  '5': { entityType: 'MATERIAL', readPermission: PERMISSIONS.READ_MATERIALS, writePermission: PERMISSIONS.WRITE_MATERIALS, deletePermission: PERMISSIONS.DELETE_MATERIALS, idField: 'materialId' },
  '6': { entityType: 'PRODUCTION_PLAN', readPermission: PERMISSIONS.READ_PRODUCTION_PLANS, writePermission: PERMISSIONS.WRITE_PRODUCTION_PLANS, deletePermission: PERMISSIONS.DELETE_PRODUCTION_PLANS, idField: 'productionPlanId' },
  '7': { entityType: 'WORK_ORDER', readPermission: PERMISSIONS.READ_WORK_ORDERS, writePermission: PERMISSIONS.WRITE_WORK_ORDERS, deletePermission: PERMISSIONS.DELETE_WORK_ORDERS, idField: 'workOrderId' },
  '8': { entityType: 'WORK_RESULT', readPermission: PERMISSIONS.READ_WORK_RESULTS, writePermission: PERMISSIONS.WRITE_WORK_RESULTS, deletePermission: PERMISSIONS.DELETE_WORK_RESULTS, idField: 'workResultId' },
  '9': { entityType: 'QUALITY_RESULT', readPermission: PERMISSIONS.READ_QUALITY_RESULTS, writePermission: PERMISSIONS.WRITE_QUALITY_RESULTS, deletePermission: PERMISSIONS.DELETE_QUALITY_RESULTS, idField: 'qualityResultId' },
  '10': { entityType: 'PROGRESS', readPermission: PERMISSIONS.READ_PROGRESS, writePermission: PERMISSIONS.WRITE_PROGRESS, deletePermission: PERMISSIONS.DELETE_PROGRESS, idField: 'progressId' },
  '11': { entityType: 'PROCEDURE', readPermission: PERMISSIONS.READ_PROCEDURES, writePermission: PERMISSIONS.WRITE_PROCEDURES, deletePermission: PERMISSIONS.DELETE_PROCEDURES, idField: 'procedureId' },
  '12': { entityType: 'QUALITY_STANDARD', readPermission: PERMISSIONS.READ_QUALITY_STANDARDS, writePermission: PERMISSIONS.WRITE_QUALITY_STANDARDS, deletePermission: PERMISSIONS.DELETE_QUALITY_STANDARDS, idField: 'qualityStandardId' },
  '13': { entityType: 'WORK_HISTORY', readPermission: PERMISSIONS.READ_WORK_HISTORY, writePermission: PERMISSIONS.WRITE_WORK_HISTORY, deletePermission: PERMISSIONS.DELETE_WORK_HISTORY, idField: 'workHistoryId' },
  '14': { entityType: 'ANOMALY_LOG', readPermission: PERMISSIONS.READ_ANOMALY_LOGS, writePermission: PERMISSIONS.WRITE_ANOMALY_LOGS, deletePermission: PERMISSIONS.DELETE_ANOMALY_LOGS, idField: 'anomalyId' },
  '15': { entityType: 'ALERT_HISTORY', readPermission: PERMISSIONS.READ_ALERT_HISTORY, writePermission: PERMISSIONS.WRITE_ALERT_HISTORY, deletePermission: PERMISSIONS.DELETE_ALERT_HISTORY, idField: 'alertHistoryId' }
};

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

function getUserFromEvent(event: APIGatewayProxyEvent) {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  if (!authHeader) {
    throw new Error('Authorization header missing');
  }
  
  const token = authHeader.replace('Bearer ', '');
  const [userId, role] = token.split(':');
  
  if (!userId || !role || !['admin', 'operator', 'viewer'].includes(role)) {
    throw new Error('Invalid token format');
  }
  
  return createUser(userId, role as 'admin' | 'operator' | 'viewer');
}

async function writeAuditLog(action: string, entityType: string, entityId: string, userId: string, details?: any) {
  const auditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    action,
    entityType,
    entityId,
    userId,
    timestamp: new Date().toISOString(),
    details: details || {}
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditLog
  }));
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return createResponse(200, {});
    }

    const user = getUserFromEvent(event);
    const path = event.path;
    const method = event.httpMethod;
    
    if (path === '/resources' && method === 'GET') {
      if (!hasPermission(user, PERMISSIONS.READ_USERS)) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }
      
      const result = await docClient.send(new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'begins_with(pk, :prefix)',
        ExpressionAttributeValues: {
          ':prefix': 'USER'
        }
      }));
      
      return createResponse(200, { items: result.Items || [] });
    }
    
    const pathMatch = path.match(/^\/api\/(\d+)(?:\/(\w+))?(?:\/(\w+))?$/);
    if (!pathMatch) {
      return createResponse(404, { error: 'Resource not found' });
    }
    
    const [, resourceIndex, resourceId, action] = pathMatch;
    const config = RESOURCE_CONFIGS[resourceIndex];
    
    if (!config) {
      return createResponse(404, { error: 'Resource not found' });
    }
    
    if (action === 'bulk' && method === 'POST') {
      if (!hasPermission(user, PERMISSIONS.BULK_IMPORT)) {
        return createResponse(403, { error: 'Insufficient permissions for bulk import' });
      }
      
      const body = JSON.parse(event.body || '{}');
      const items = body.items || [];
      
      if (!Array.isArray(items)) {
        return createResponse(400, { error: 'Items must be an array' });
      }
      
      let imported = 0;
      let failed = 0;
      const errors: string[] = [];
      
      const chunks = [];
      for (let i = 0; i < items.length; i += 25) {
        chunks.push(items.slice(i, i + 25));
      }
      
      for (const chunk of chunks) {
        const writeRequests = chunk.map(item => {
          const id = item.id || randomUUID();
          const now = new Date().toISOString();
          
          return {
            PutRequest: {
              Item: {
                pk: config.entityType,
                sk: id,
                [config.idField]: id,
                ...item,
                createdAt: now,
                updatedAt: now,
                createdBy: user.id
              }
            }
          };
        });
        
        try {
          await docClient.send(new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: writeRequests
            }
          }));
          imported += chunk.length;
        } catch (error) {
          failed += chunk.length;
          errors.push(`Batch write failed: ${error}`);
        }
      }
      
      await writeAuditLog('BULK_IMPORT', config.entityType, 'BULK', user.id, { imported, failed });
      
      return createResponse(200, { imported, failed, errors });
    }
    
    if (method === 'GET') {
      if (!hasPermission(user, config.readPermission)) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }
      
      if (resourceId) {
        const result = await docClient.send(new GetCommand({
          TableName: TABLE_NAME,
          Key: {
            pk: config.entityType,
            sk: resourceId
          }
        }));
        
        if (!result.Item) {
          return createResponse(404, { error: 'Resource not found' });
        }
        
        return createResponse(200, result.Item);
      } else {
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'pk = :pk',
          ExpressionAttributeValues: {
            ':pk': config.entityType
          }
        }));
        
        return createResponse(200, { items: result.Items || [] });
      }
    }
    
    if (method === 'POST') {
      if (!hasPermission(user, config.writePermission)) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }
      
      const body = JSON.parse(event.body || '{}');
      const id = randomUUID();
      const now = new Date().toISOString();
      
      const item = {
        pk: config.entityType,
        sk: id,
        [config.idField]: id,
        ...body,
        createdAt: now,
        updatedAt: now,
        createdBy: user.id
      };
      
      await docClient.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: item
      }));
      
      await writeAuditLog('CREATE', config.entityType, id, user.id, body);
      
      return createResponse(201, item);
    }
    
    if (method === 'PUT' && resourceId) {
      if (!hasPermission(user, config.writePermission)) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }
      
      const body = JSON.parse(event.body || '{}');
      const now = new Date().toISOString();
      
      const existing = await docClient.send(new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: config.entityType,
          sk: resourceId
        }
      }));
      
      if (!existing.Item) {
        return createResponse(404, { error: 'Resource not found' });
      }
      
      const item = {
        ...existing.Item,
        ...body,
        updatedAt: now,
        updatedBy: user.id
      };
      
      await docClient.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: item
      }));
      
      await writeAuditLog('UPDATE', config.entityType, resourceId, user.id, body);
      
      return createResponse(200, item);
    }
    
    if (method === 'DELETE' && resourceId) {
      if (!hasPermission(user, config.deletePermission)) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }
      
      const existing = await docClient.send(new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: config.entityType,
          sk: resourceId
        }
      }));
      
      if (!existing.Item) {
        return createResponse(404, { error: 'Resource not found' });
      }
      
      await docClient.send(new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: config.entityType,
          sk: resourceId
        }
      }));
      
      await writeAuditLog('DELETE', config.entityType, resourceId, user.id);
      
      return createResponse(200, { message: 'Resource deleted successfully' });
    }
    
    return createResponse(405, { error: 'Method not allowed' });
    
  } catch (error) {
    console.error('Error:', error);
    
    if (error instanceof Error) {
      if (error.message.includes('Authorization') || error.message.includes('token')) {
        return createResponse(401, { error: 'Unauthorized' });
      }
      if (error.message.includes('permissions')) {
        return createResponse(403, { error: 'Forbidden' });
      }
      if (error.message.includes('not found')) {
        return createResponse(404, { error: 'Not found' });
      }
      if (error.message.includes('validation')) {
        return createResponse(400, { error: error.message });
      }
    }
    
    return createResponse(500, { error: 'Internal server error' });
  }
};