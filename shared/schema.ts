import { z } from 'zod';

// Export TypeScript types based on Prisma schema
export type Session = {
  sid: string;
  sess: string;
  expire: Date;
};
export type User = {
  id: string;
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  profileImageUrl?: string | null;
  role: string;
  isActive: boolean;
  lastLoginAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type Project = {
  id: string;
  name: string;
  projectNumber?: string | null;
  description?: string | null;
  color?: string;
  startDate?: Date | null;
  endDate?: Date | null;
  isEnterpriseWide: boolean;
  userId: string;
  createdAt: Date;
  updatedAt: Date;
};

export type Task = {
  id: string;
  projectId: string;
  name: string;
  description?: string | null;
  status: string;
  createdAt: Date;
  updatedAt: Date;
};

export type TimeEntry = {
  id: string;
  userId: string;
  projectId: string;
  taskId?: string | null;
  description?: string | null;
  date: Date;
  startTime: string;
  endTime: string;
  duration: number;
  createdAt: Date;
  updatedAt: Date;
};

export type Employee = {
  id: string;
  employeeId: string;
  firstName: string;
  lastName: string;
  email?: string | null;
  phone?: string | null;
  department: string;
  position?: string | null;
  managerId?: string | null;
  hireDate?: Date | null;
  salary?: number | null;
  isActive: boolean;
  employmentType: string;
  userId: string;
  createdAt: Date;
  updatedAt: Date;
};

export type ProjectEmployee = {
  id: string;
  projectId: string;
  employeeId: string;
  userId: string;
  createdAt: Date;
};

export type ProjectWithEmployees = Project & {
  assignedEmployees?: Employee[];
};

// Zod validation schemas for forms
export const insertProjectSchema = z.object({
  name: z.string().min(1, "Project name is required"),
  projectNumber: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  color: z.string().default('#1976D2'),
  startDate: z.coerce.date().optional().nullable(),
  endDate: z.coerce.date().optional().nullable(),
  isEnterpriseWide: z.boolean().default(true),
});

export const insertTaskSchema = z.object({
  projectId: z.string(),
  name: z.string().min(1, "Task name is required"),
  description: z.string().optional().nullable(),
  status: z.string().default('active'),
});

export const insertTimeEntrySchema = z.object({
  userId: z.string(),
  projectId: z.string(),
  taskId: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  date: z.date(),
  startTime: z.string(),
  endTime: z.string(),
  duration: z.number(),
});

export const insertEmployeeSchema = z.object({
  employeeId: z.string().min(1, "Employee ID is required"),
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
  email: z.string().email().optional().nullable(),
  phone: z.string().optional().nullable(),
  department: z.string().min(1, "Department is required"),
  position: z.string().optional().nullable(),
  managerId: z.string().optional().nullable(),
  hireDate: z.coerce.date().optional().nullable(),
  salary: z.number().optional().nullable(),
  isActive: z.boolean().default(true),
  employmentType: z.string().default("full-time"),
  userId: z.string(),
});

export const insertProjectEmployeeSchema = z.object({
  projectId: z.string(),
  employeeId: z.string(),
  userId: z.string(),
});

// Organization and Department types
export type Organization = {
  id: string;
  name: string;
  description?: string | null;
  userId: string;
  createdAt: Date;
  updatedAt: Date;
};

export type Department = {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  managerId?: string | null;
  userId: string;
  createdAt: Date;
  updatedAt: Date;
};

export type OrganizationWithDepartments = Organization & {
  departments?: Department[];
};

export type DepartmentWithEmployees = Department & {
  employees?: Employee[];
};

// Organization and Department validation schemas
export const insertOrganizationSchema = z.object({
  name: z.string().min(1, "Organization name is required"),
  description: z.string().optional().nullable(),
  userId: z.string(),
});

export const insertDepartmentSchema = z.object({
  name: z.string().min(1, "Department name is required"),
  description: z.string().optional().nullable(),
  organizationId: z.string(),
  managerId: z.string().optional().nullable(),
  userId: z.string(),
});