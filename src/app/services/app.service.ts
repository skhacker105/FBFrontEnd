import { Injectable } from '@angular/core';
import { DBContext, MultiDBManager } from '../indexeddb-handler';

@Injectable({
  providedIn: 'root'
})
export class AppService {
  title = 'First Book';
  private mgr = new MultiDBManager();

  get deviceId(): string | null {
    return this.mgr.getDeviceId();
  }

  get selectedDB(): DBContext | null {
    return this.mgr.getSelectedDB();
  }

  get selectedDBId(): string | null {
    return this.mgr.getSelectedDB()?.dbId ?? null;
  }

  get creatorDeviceId(): string | null {
    return this.mgr.getSelectedDB()?.creatorDeviceId ?? null
  }

  constructor() { }

  setDeviceId(deviceId: string): void {
    this.mgr.setDeviceId(deviceId);
  }

  // ---------- DB flows ----------
  createDatabaseAsCreator(dbId: string, schema: any) {
    return this.mgr.createDatabaseAsCreator(dbId, schema);
  }

  async joinAsDeviceFromImport(importDB: string) {
    return await this.mgr.joinAsDeviceFromImport(importDB);
  }

  addDevice(newDeviceId: string, role: string) {
    if (!this.selectedDBId) return;
    return this.mgr.addDevice(newDeviceId, role);
  }

  async generateConnectionKey(deviceId: string): Promise<string> {
    if (!this.deviceId) return '';
    return await this.mgr.generateConnectionKey(deviceId);
  }

  resetDevice(removeDB = true) {
    localStorage.removeItem(`multiDBManager_dbs`);
    localStorage.removeItem('multiDBManager_selectedDB');
    localStorage.removeItem(`secrets_${this.selectedDBId}_${this.deviceId}`);
    if (removeDB) {
      indexedDB.deleteDatabase('idb:' + (this.selectedDBId ?? ''));
    }
  }


  // ---------- CRUD (entity-specific wrapper) ----------
  async addTask(id: string, title: string, description: string, status: string) {
    if (!this.selectedDBId) return;
    const task = { id, title, description, status }
    return this.mgr.put(this.selectedDBId, 'tasks', task);
  }

  async getTask(id: string) {
    if (!this.selectedDBId) return;
    return this.mgr.get(this.selectedDBId, 'tasks', id);
  }

  async deleteTask(id: string) {
    if (!this.selectedDBId) return;
    return this.mgr.delete(this.selectedDBId, 'tasks', id);
  }

  async searchTask(text: string) {
    if (!this.selectedDBId) return;
    return this.mgr.search(this.selectedDBId, 'tasks', { text, fields: ['title'], minMatch: 'ALL' });
  }

  // ---------- Listing ----------
  listDevices() {
    if (!this.selectedDBId) return [];
    return this.mgr.listDevices(this.selectedDBId);
  }

  listRoles() {
    if (!this.selectedDBId) return [];
    return this.mgr.listRoles(this.selectedDBId);
  }

  // ---------- Selected DB ----------
  selectDB(dbId: string) {
    this.mgr.selectDB(dbId);
  }

  resetSelectedDB() {
    this.mgr.resetSelectedDB();
  }
}
