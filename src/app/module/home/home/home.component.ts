import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AppService } from '../../../services/app.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent {
  isLoggedIn: boolean = true; // Simulate login state; in real app, use auth service
  modules: { name: string, route: string, description: string, iconUrl: string }[] = [
    { name: 'Products', route: '/products', description: 'Manage your product inventory and details.', iconUrl: 'https://img.icons8.com/ios/100/box--v1.png' },
    { name: 'Store', route: '/store', description: 'Handle store operations and sales.', iconUrl: 'https://img.icons8.com/ios/100/shop--v1.png' },
    { name: 'Finance', route: '/finance', description: 'Track financial transactions and budgets.', iconUrl: 'https://img.icons8.com/ios/100/banknotes--v1.png' },
    { name: 'Billings', route: '/billings', description: 'Generate and manage invoices and bills.', iconUrl: 'https://img.icons8.com/ios/100/billing--v1.png' },
    { name: 'Orders', route: '/orders', description: 'Process customer orders and shipments.', iconUrl: 'https://img.icons8.com/ios/100/purchase-order--v1.png' },
    { name: 'Employees', route: '/employees', description: 'Manage employee records and HR tasks.', iconUrl: 'https://img.icons8.com/ios/100/conference--v1.png' },
    { name: 'Attendance', route: '/attendance', description: 'Track employee attendance and leaves.', iconUrl: 'https://img.icons8.com/ios/100/time-card--v1.png' },
    { name: 'Reports', route: '/reports', description: 'Generate business reports and analytics.', iconUrl: 'https://img.icons8.com/ios/100/bar-chart--v1.png' },
    { name: 'Manufacturing', route: '/manufacturing', description: 'Oversee production and manufacturing processes.', iconUrl: 'https://img.icons8.com/ios/100/factory--v1.png' }
    // Add more modules as needed
  ];

  constructor(private router: Router, public appService: AppService) {}

  ngOnInit(): void {
    // In a real app, check auth status here, e.g., from a service
    // this.isLoggedIn = this.authService.isLoggedIn();
  }

  toggleLogin(): void {
    if (this.isLoggedIn) {
      // Logout logic
      this.isLoggedIn = false;
      this.router.navigate(['/']); // Redirect to home after logout
    } else {
      // Navigate to login page
      this.router.navigate(['/login']);
    }
  }

  navigateToAbout(): void {
    this.router.navigate(['/about']);
  }

  navigateToModule(route: string): void {
    this.router.navigate([route]);
  }
}
