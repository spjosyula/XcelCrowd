import { Response, NextFunction } from 'express';
import { BaseController } from './BaseController';
import { DashboardService } from '../services/dashboard.service';
import { AuthRequest } from '../types/request.types';
import { catchAsync } from '../utils/catch.async';
import { ArchitectService } from '../services/architect.service';
import { UserRole } from '../models/interfaces';

/**
 * Controller for dashboard-related operations
 * Extends BaseController for standardized response handling
 */
export class DashboardController extends BaseController {
  private dashboardService: DashboardService;
  private architectService: ArchitectService;

  constructor() {
    super();
    this.dashboardService = new DashboardService();
    this.architectService = new ArchitectService();
  }

  public getStudentDashboard = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has student role
      this.verifyAuthorization(req, [UserRole.STUDENT], 'accessing student dashboard');
      
      const stats = await this.dashboardService.getStudentDashboardStats(req.user!.userId);
      
      // Log the action
      this.logAction('student-dashboard-access', req.user!.userId);
      
      this.sendSuccess(res, stats, 'Student dashboard statistics retrieved successfully');
    }
  );

  public getCompanyDashboard = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has company role
      this.verifyAuthorization(req, [UserRole.COMPANY], 'accessing company dashboard');
      
      const stats = await this.dashboardService.getCompanyDashboardStats(req.user!.userId);
      
      // Log the action
      this.logAction('company-dashboard-access', req.user!.userId);
      
      this.sendSuccess(res, stats, 'Company dashboard statistics retrieved successfully');
    }
  );

  public getArchitectDashboard = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has architect role
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'accessing architect dashboard');
      
      const stats = await this.architectService.getDashboardStats(req.user!.userId);
      
      // Log the action
      this.logAction('architect-dashboard-access', req.user!.userId);
      
      this.sendSuccess(res, stats, 'Architect dashboard statistics retrieved successfully');
    }
  );
}

// Export singleton instance for use in routes
export const dashboardController = new DashboardController();