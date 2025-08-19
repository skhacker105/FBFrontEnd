import { Component, HostListener, OnDestroy, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AppService } from '../../../services/app.service';
import { Subject, debounceTime, takeUntil } from 'rxjs';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent implements OnInit, OnDestroy {
  isLoggedIn: boolean = true;
  showModulesMenu: boolean = false;
  showAddMenu: boolean = false;
  isMobileView: boolean = window.innerWidth <= 767;
  private resizeSubject = new Subject<Event>();
  private destroy$ = new Subject<void>();

  modules: { name: string, route: string, description: string, iconUrl: string, subLinks: { name: string, route: string }[] }[] = [
    {
      name: 'Products', route: '/products', description: 'Manage your product inventory and details.', iconUrl: 'https://img.icons8.com/ios/100/box--v1.png',
      subLinks: [
        { name: 'Add Product', route: '/products/add' },
        { name: 'Edit Product', route: '/products/edit' },
        { name: 'View Products', route: '/products/view' },
        { name: 'Search Products', route: '/products/search' }
      ]
    },
    {
      name: 'Store', route: '/store', description: 'Handle store operations and sales.', iconUrl: 'https://img.icons8.com/ios/100/shop--v1.png',
      subLinks: [
        { name: 'Add Item', route: '/store/add' },
        { name: 'Manage Sales', route: '/store/sales' },
        { name: 'View Inventory', route: '/store/view' }
      ]
    },
    {
      name: 'Finance', route: '/finance', description: 'Track financial transactions and budgets.', iconUrl: 'https://img.icons8.com/ios/100/banknotes--v1.png',
      subLinks: [
        { name: 'Add Transaction', route: '/finance/add' },
        { name: 'View Budgets', route: '/finance/budgets' },
        { name: 'Generate Report', route: '/finance/report' }
      ]
    },
    {
      name: 'Billings', route: '/billings', description: 'Generate and manage invoices and bills.', iconUrl: 'https://img.icons8.com/ios/100/billing--v1.png',
      subLinks: [
        { name: 'Purchase Bill', route: '/billings/purchase' },
        { name: 'Sales Bill', route: '/billings/sales' },
        { name: 'Bill with Order', route: '/billings/order' }
      ]
    },
    {
      name: 'Orders', route: '/orders', description: 'Process customer orders and shipments.', iconUrl: 'https://img.icons8.com/ios/100/purchase-order--v1.png',
      subLinks: [
        { name: 'Add Order', route: '/orders/add' },
        { name: 'Track Shipment', route: '/orders/track' },
        { name: 'View Orders', route: '/orders/view' }
      ]
    },
    {
      name: 'Employees', route: '/employees', description: 'Manage employee records and HR tasks.', iconUrl: 'https://img.icons8.com/ios/100/conference--v1.png',
      subLinks: [
        { name: 'Add Employee', route: '/employees/add' },
        { name: 'Edit Records', route: '/employees/edit' },
        { name: 'View Employees', route: '/employees/view' }
      ]
    },
    {
      name: 'Attendance', route: '/attendance', description: 'Track employee attendance and leaves.', iconUrl: 'https://img.icons8.com/ios/100/time-card--v1.png',
      subLinks: [
        { name: 'Mark Attendance', route: '/attendance/mark' },
        { name: 'View Leaves', route: '/attendance/leaves' },
        { name: 'Generate Report', route: '/attendance/report' }
      ]
    },
    {
      name: 'Reports', route: '/reports', description: 'Generate business reports and analytics.', iconUrl: 'https://img.icons8.com/ios/100/bar-chart--v1.png',
      subLinks: [
        { name: 'Sales Report', route: '/reports/sales' },
        { name: 'Finance Report', route: '/reports/finance' },
        { name: 'Custom Report', route: '/reports/custom' }
      ]
    },
    {
      name: 'Manufacturing', route: '/manufacturing', description: 'Oversee production and manufacturing processes.', iconUrl: 'https://img.icons8.com/ios/100/factory--v1.png',
      subLinks: [
        { name: 'Add Process', route: '/manufacturing/add' },
        { name: 'Monitor Production', route: '/manufacturing/monitor' },
        { name: 'View Logs', route: '/manufacturing/view' }
      ]
    }
  ];

  constructor(private router: Router, public appService: AppService) { }

  ngOnInit(): void {
    // Set up resize listener with debounce
    this.resizeSubject.pipe(
      debounceTime(100),
      takeUntil(this.destroy$)
    ).subscribe(() => {
      this.isMobileView = window.innerWidth <= 767;
    });
  }

  @HostListener('window:resize', ['$event'])
  onResize(event: Event): void {
    this.resizeSubject.next(event);
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  toggleLogin(): void {
    if (this.isLoggedIn) {
      this.isLoggedIn = false;
      this.router.navigate(['/']);
    } else {
      this.router.navigate(['/login']);
    }
  }

  navigateToAbout(): void {
    this.router.navigate(['/about']);
  }

  navigateToModule(route: string): void {
    this.router.navigate([route]);
    this.showModulesMenu = false;
  }

  toggleModulesMenu(): void {
    this.showModulesMenu = !this.showModulesMenu;
    this.showAddMenu = false; // Close add menu if open
  }

  toggleAddMenu(): void {
    this.showAddMenu = !this.showAddMenu;
    this.showModulesMenu = false; // Close modules menu if open
  }
}
