import { Component } from '@angular/core';
import { AppService } from './services/app.service';
import { SecretBundle, fromB64, toB64 } from './indexeddb-handler';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {

  deviceId: string = '';
  dbId: string = '';
  importDB: string = '';
  newDeviceId: string = '';
  role: string = '';
  device: string = '';

  devices: any[] = [];
  dbConnectionKey = '';
  roles: any[] = [];

  schema = {
    version: 1,
    stores: {
      tasks: {
        keyPath: 'id',
        indexes: [{ name: 'byTitle', keyPath: 'title', options: { multiEntry: true } }],
        secureIndex: ['title', 'description', 'status']
      }
    }
  };

  constructor(public appService: AppService) {
  }

  async loadAllDevices() {
    const devices = await this.appService.listDevices();
    this.devices = devices.filter(d => this.appService.deviceId != d.deviceId)
  }

  async loadAllRoles() {
    const roles = await this.appService.listRoles();
    this.roles = roles.filter(r => r.role != 'creator');
  }

  reviveSecretBundle(raw: any): SecretBundle {
    return {
      ...raw,
      dekRaw: fromB64(raw.dekRaw),
      indexKeyRaw: fromB64(raw.indexKeyRaw),
      devicePubJwk: raw.devicePubJwk,          // stays object
      devicePrivJwk: raw.devicePrivJwk,        // stays object
      // if you stored others, revive them too
    };
  }

  loadConnectionString(importDB: string) {
    try {
      this.appService.joinAsDeviceFromImport(importDB)
        .then(ctx => {
          console.log('Joined DB as device:', ctx);
        })
        .catch(err => {
          console.error('Failed to join DB:', err);
        });
    } catch (err) {
      console.error('Invalid connection string', err);
    }
    // if (!this.appService.selectedDBId) return;

  }

  async generateDBConnectionKey(deviceId: string) {
    this.dbConnectionKey = '';
    this.dbConnectionKey = await this.appService.generateConnectionKey(deviceId);

  }

  addDevice(deviceId: string, role: string) {
    if (!deviceId || !role) return;

    this.appService.addDevice(deviceId, role)
  }

  async searchTask(text: string) {
    const result = await this.appService.searchTask(text);
    console.log(`Searching text ${text} result = `, result);
  }
}
