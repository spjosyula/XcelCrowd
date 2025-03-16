import { Request, Response, NextFunction } from 'express';
import { UserService, CreateUserDTO, UpdateUserDTO } from '../services/user.service';
import { HTTP_STATUS } from '../constants';
import { ApiResponse } from '../utils/ApiResponse';
import { catchAsync } from '../utils/catchAsync';

/**
 * User controller for handling user-related HTTP requests
 */
export class UserController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  /**
   * Create a new user
   */
  public createUser = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const userData: CreateUserDTO = req.body;
      const user = await this.userService.createUser(userData);
      
      res.status(HTTP_STATUS.CREATED).json(
        ApiResponse.success(user, 'User created successfully')
      );
    }
  );

  /**
   * Get user by ID
   */
  public getUserById = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;
      const user = await this.userService.getUserById(id);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(user, 'User retrieved successfully')
      );
    }
  );

  /**
   * Update user
   */
  public updateUser = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;
      const updateData: UpdateUserDTO = req.body;
      const user = await this.userService.updateUser(id, updateData);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(user, 'User updated successfully')
      );
    }
  );

  /**
   * Delete user
   */
  public deleteUser = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;
      await this.userService.deleteUser(id);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(null, 'User deleted successfully')
      );
    }
  );
}
