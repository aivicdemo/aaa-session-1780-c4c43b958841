export type Role = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  role: Role;
  permissions: string[];
}

export const PERMISSIONS = {
  READ_USERS: 'read:users',
  WRITE_USERS: 'write:users',
  DELETE_USERS: 'delete:users',
  READ_PRODUCTS: 'read:products',
  WRITE_PRODUCTS: 'write:products',
  DELETE_PRODUCTS: 'delete:products',
  READ_SPECIFICATIONS: 'read:specifications',
  WRITE_SPECIFICATIONS: 'write:specifications',
  DELETE_SPECIFICATIONS: 'delete:specifications',
  READ_PROCESSES: 'read:processes',
  WRITE_PROCESSES: 'write:processes',
  DELETE_PROCESSES: 'delete:processes',
  READ_LINES: 'read:lines',
  WRITE_LINES: 'write:lines',
  DELETE_LINES: 'delete:lines',
  READ_MATERIALS: 'read:materials',
  WRITE_MATERIALS: 'write:materials',
  DELETE_MATERIALS: 'delete:materials',
  READ_PRODUCTION_PLANS: 'read:production_plans',
  WRITE_PRODUCTION_PLANS: 'write:production_plans',
  DELETE_PRODUCTION_PLANS: 'delete:production_plans',
  READ_WORK_ORDERS: 'read:work_orders',
  WRITE_WORK_ORDERS: 'write:work_orders',
  DELETE_WORK_ORDERS: 'delete:work_orders',
  READ_WORK_RESULTS: 'read:work_results',
  WRITE_WORK_RESULTS: 'write:work_results',
  DELETE_WORK_RESULTS: 'delete:work_results',
  READ_QUALITY_RESULTS: 'read:quality_results',
  WRITE_QUALITY_RESULTS: 'write:quality_results',
  DELETE_QUALITY_RESULTS: 'delete:quality_results',
  READ_PROGRESS: 'read:progress',
  WRITE_PROGRESS: 'write:progress',
  DELETE_PROGRESS: 'delete:progress',
  READ_PROCEDURES: 'read:procedures',
  WRITE_PROCEDURES: 'write:procedures',
  DELETE_PROCEDURES: 'delete:procedures',
  READ_QUALITY_STANDARDS: 'read:quality_standards',
  WRITE_QUALITY_STANDARDS: 'write:quality_standards',
  DELETE_QUALITY_STANDARDS: 'delete:quality_standards',
  READ_WORK_HISTORY: 'read:work_history',
  WRITE_WORK_HISTORY: 'write:work_history',
  DELETE_WORK_HISTORY: 'delete:work_history',
  READ_ANOMALY_LOGS: 'read:anomaly_logs',
  WRITE_ANOMALY_LOGS: 'write:anomaly_logs',
  DELETE_ANOMALY_LOGS: 'delete:anomaly_logs',
  READ_ALERT_HISTORY: 'read:alert_history',
  WRITE_ALERT_HISTORY: 'write:alert_history',
  DELETE_ALERT_HISTORY: 'delete:alert_history',
  BULK_IMPORT: 'bulk:import'
} as const;

export const ROLE_PERMISSIONS: Record<Role, string[]> = {
  admin: Object.values(PERMISSIONS),
  operator: [
    PERMISSIONS.READ_USERS,
    PERMISSIONS.READ_PRODUCTS,
    PERMISSIONS.WRITE_PRODUCTS,
    PERMISSIONS.READ_SPECIFICATIONS,
    PERMISSIONS.WRITE_SPECIFICATIONS,
    PERMISSIONS.READ_PROCESSES,
    PERMISSIONS.WRITE_PROCESSES,
    PERMISSIONS.READ_LINES,
    PERMISSIONS.WRITE_LINES,
    PERMISSIONS.READ_MATERIALS,
    PERMISSIONS.WRITE_MATERIALS,
    PERMISSIONS.READ_PRODUCTION_PLANS,
    PERMISSIONS.WRITE_PRODUCTION_PLANS,
    PERMISSIONS.READ_WORK_ORDERS,
    PERMISSIONS.WRITE_WORK_ORDERS,
    PERMISSIONS.READ_WORK_RESULTS,
    PERMISSIONS.WRITE_WORK_RESULTS,
    PERMISSIONS.READ_QUALITY_RESULTS,
    PERMISSIONS.WRITE_QUALITY_RESULTS,
    PERMISSIONS.READ_PROGRESS,
    PERMISSIONS.WRITE_PROGRESS,
    PERMISSIONS.READ_PROCEDURES,
    PERMISSIONS.WRITE_PROCEDURES,
    PERMISSIONS.READ_QUALITY_STANDARDS,
    PERMISSIONS.WRITE_QUALITY_STANDARDS,
    PERMISSIONS.READ_WORK_HISTORY,
    PERMISSIONS.WRITE_WORK_HISTORY,
    PERMISSIONS.READ_ANOMALY_LOGS,
    PERMISSIONS.WRITE_ANOMALY_LOGS,
    PERMISSIONS.READ_ALERT_HISTORY,
    PERMISSIONS.WRITE_ALERT_HISTORY,
    PERMISSIONS.BULK_IMPORT
  ],
  viewer: [
    PERMISSIONS.READ_USERS,
    PERMISSIONS.READ_PRODUCTS,
    PERMISSIONS.READ_SPECIFICATIONS,
    PERMISSIONS.READ_PROCESSES,
    PERMISSIONS.READ_LINES,
    PERMISSIONS.READ_MATERIALS,
    PERMISSIONS.READ_PRODUCTION_PLANS,
    PERMISSIONS.READ_WORK_ORDERS,
    PERMISSIONS.READ_WORK_RESULTS,
    PERMISSIONS.READ_QUALITY_RESULTS,
    PERMISSIONS.READ_PROGRESS,
    PERMISSIONS.READ_PROCEDURES,
    PERMISSIONS.READ_QUALITY_STANDARDS,
    PERMISSIONS.READ_WORK_HISTORY,
    PERMISSIONS.READ_ANOMALY_LOGS,
    PERMISSIONS.READ_ALERT_HISTORY
  ]
};

export function hasPermission(user: User, permission: string): boolean {
  return user.permissions.includes(permission);
}

export function createUser(id: string, role: Role): User {
  return {
    id,
    role,
    permissions: ROLE_PERMISSIONS[role]
  };
}