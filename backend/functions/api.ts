import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, PutCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getUserFromEvent, checkPermission, PERMISSIONS, User } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface ErrorResponse {
  error: string;
  message: string;
}

interface BulkImportRequest {
  items: Record<string, unknown>[];
}

interface BulkImportResponse {
  imported: number;
  failed: number;
  errors: string[];
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

function createErrorResponse(statusCode: number, error: string, message: string): APIGatewayProxyResult {
  const errorResponse: ErrorResponse = { error, message };
  return createResponse(statusCode, errorResponse);
}

async function createAuditLog(user: User, action: string, details: any): Promise<void> {
  const auditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    userId: user.id,
    userRole: user.role,
    action,
    details,
    timestamp: new Date().toISOString()
  };

  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditLog
  }));
}

async function getResources(user: User): Promise<APIGatewayProxyResult> {
  try {
    checkPermission(user, PERMISSIONS.RESOURCES_READ);

    const command = new ScanCommand({
      TableName: TABLE_NAME,
      FilterExpression: 'pk <> :auditPk',
      ExpressionAttributeValues: {
        ':auditPk': 'AUDIT'
      }
    });

    const result = await docClient.send(command);
    return createResponse(200, {
      items: result.Items || [],
      count: result.Count || 0
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Insufficient permissions')) {
      return createErrorResponse(403, 'Forbidden', error.message);
    }
    console.error('Error getting resources:', error);
    return createErrorResponse(500, 'Internal Server Error', 'Failed to retrieve resources');
  }
}

async function bulkImport(user: User, tableIndex: string, items: Record<string, unknown>[]): Promise<APIGatewayProxyResult> {
  try {
    checkPermission(user, PERMISSIONS.BULK_IMPORT);

    if (!items || !Array.isArray(items)) {
      return createErrorResponse(400, 'Bad Request', 'Items must be an array');
    }

    if (items.length === 0) {
      return createResponse(200, { imported: 0, failed: 0, errors: [] });
    }

    const now = new Date().toISOString();
    const processedItems = items.map(item => ({
      ...item,
      id: item.id || randomUUID(),
      createdAt: now,
      updatedAt: now,
      pk: item.pk || `RESOURCE_${tableIndex}`,
      sk: item.sk || `${Date.now()}_${randomUUID()}`
    }));

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    // Process in batches of 25 (DynamoDB BatchWrite limit)
    for (let i = 0; i < processedItems.length; i += 25) {
      const batch = processedItems.slice(i, i + 25);
      
      try {
        const putRequests = batch.map(item => ({
          PutRequest: {
            Item: item
          }
        }));

        const command = new BatchWriteCommand({
          RequestItems: {
            [TABLE_NAME]: putRequests
          }
        });

        const result = await docClient.send(command);
        
        // Handle unprocessed items
        const unprocessedCount = result.UnprocessedItems?.[TABLE_NAME]?.length || 0;
        imported += (batch.length - unprocessedCount);
        failed += unprocessedCount;
        
        if (unprocessedCount > 0) {
          errors.push(`Batch ${Math.floor(i/25) + 1}: ${unprocessedCount} items failed to process`);
        }
      } catch (batchError) {
        failed += batch.length;
        errors.push(`Batch ${Math.floor(i/25) + 1}: ${batchError instanceof Error ? batchError.message : 'Unknown error'}`);
      }
    }

    // Create audit log
    await createAuditLog(user, 'BULK_IMPORT', {
      tableIndex,
      totalItems: items.length,
      imported,
      failed
    });

    const response: BulkImportResponse = {
      imported,
      failed,
      errors
    };

    return createResponse(200, response);
  } catch (error) {
    if (error instanceof Error && error.message.includes('Insufficient permissions')) {
      return createErrorResponse(403, 'Forbidden', error.message);
    }
    console.error('Error in bulk import:', error);
    return createErrorResponse(500, 'Internal Server Error', 'Failed to import items');
  }
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const user = getUserFromEvent(event);
    const method = event.httpMethod;
    const path = event.path;
    const pathParameters = event.pathParameters || {};

    console.log(`Processing ${method} ${path} for user ${user.id} with role ${user.role}`);

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return createResponse(200, {});
    }

    // Route handling
    if (method === 'GET' && path === '/resources') {
      return await getResources(user);
    }

    // Bulk import endpoints
    const bulkImportMatch = path.match(/^\/api\/(\w+)\/bulk$/);
    if (method === 'POST' && bulkImportMatch) {
      const tableIndex = bulkImportMatch[1];
      let requestBody: BulkImportRequest;
      
      try {
        requestBody = JSON.parse(event.body || '{}');
      } catch (parseError) {
        return createErrorResponse(400, 'Bad Request', 'Invalid JSON in request body');
      }

      return await bulkImport(user, tableIndex, requestBody.items);
    }

    return createErrorResponse(404, 'Not Found', `Endpoint ${method} ${path} not found`);
  } catch (error) {
    console.error('Unhandled error:', error);
    return createErrorResponse(500, 'Internal Server Error', 'An unexpected error occurred');
  }
};