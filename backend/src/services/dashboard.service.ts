import { SolutionService } from './solution.service';
import { ChallengeService } from './challenge.service';
import { UserService } from './user.service';

export class DashboardService {
  private solutionService: SolutionService;
  private challengeService: ChallengeService;
  private userService: UserService;

  constructor() {
    this.solutionService = new SolutionService();
    this.challengeService = new ChallengeService();
    this.userService = new UserService();
  }

  async getStudentDashboardStats(studentId: string) {
    // // Get student specific stats by leveraging existing services
    // //const submittedSolutions = await this.solutionService.
    // const activeChallenges = await this.challengeService.getChallenges
    // // Add more statistics as needed
    
    // return {
    //   submittedSolutionsCount: submittedSolutions.length,
    //   activeChallengesCount: activeChallenges.length,
    //   // Add more stats
    // };
  }

  async getCompanyDashboardStats(companyId: string) {
    // // Get company specific stats
    // const companyChallenges = await this.challengeService.getChallengesByCompanyId(companyId);
    // const challengeIds = companyChallenges.map(c => c.id);
    // const solutions = await this.solutionService.getSolutionsForChallenges(challengeIds);
    
    // return {
    //   postedChallengesCount: companyChallenges.length,
    //   receivedSolutionsCount: solutions.length,
    //   // Add more stats
    // };
  }
}