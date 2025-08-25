import { Component } from '@angular/core';
import { AppService, fromB64, toB64 } from './services/app.service';
import { SecretBundle } from './indexeddb-handler';

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
    setTimeout(() => {
      // try to restore DB + crypto + sync from local storage
      if (this.appService.deviceId && this.appService.dbId) {
        this.appService.restoreFromLocalStorage(this.appService.deviceId, this.appService.dbId, this.schema)
          .then(ok => {
            if (ok) {
              console.log(`Restored session for device=${this.appService.deviceId}, db=${this.appService.dbId}`);
              this.loadAllDevices();
              this.loadAllRoles();
            } else {
              console.log("No previous session to restore");
            }
          });
      }
    }, 1000);
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
    if (!this.appService.deviceId) return;

    try {
      const parsed = JSON.parse(importDB);
      console.log('parsed = ', parsed);
      if (parsed.deviceId !== this.appService.deviceId) {
        console.log('device Id mismatch')
        return;
      }
      this.appService.joinAsDevice(this.appService.deviceId, parsed.role,
        parsed.dbId, this.reviveSecretBundle(parsed.secret), parsed.schema, parsed.creatorDeviceId);

    } catch (err) { console.log(`${importDB} failed to load with error ${err}`) }
  }

  generateDBConnectionKey(deviceId: string) {
    this.dbConnectionKey = '';
    console.log('this.appService.deviceId = ', this.appService.deviceId)
    console.log('this.appService.dbId = ', this.appService.dbId)
    if (!this.appService.deviceId || !this.appService.dbId) return;

    const device = this.devices.find(d => d.deviceId === deviceId);

    let secret: any = this.appService.loadSecretsFromLocalStorage(this.appService.dbId, this.appService.deviceId);
    if (!secret) return;

    secret = {
      ...secret,
      dekRaw: toB64(secret.dekRaw),
      indexKeyRaw: toB64(secret.indexKeyRaw)
    } as SecretBundle;
    this.dbConnectionKey = JSON.stringify({
      deviceId: deviceId,
      dbId: this.appService.dbId,
      role: device.role,
      schema: this.schema,
      secret,
      creatorDeviceId: this.appService.deviceId
    })
  }

  addDevice(deviceId: string, role: string) {
    if (!deviceId || !role || !this.appService.dbId || !this.appService.cryptoMgr?.devicePubJwk) return;

    this.appService.addDevice(deviceId, role, this.appService.cryptoMgr.devicePubJwk)
  }
}
