import { Authentication, User } from './user';
export interface GoogleAuthPlugin {
  signIn(): Promise<User>;
  refresh(): Promise<Authentication>;
  isSignedIn(): boolean;
  signOut(): Promise<any>;
}
