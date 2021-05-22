import { WebPlugin } from '@capacitor/core';

import type { GoogleAuthPlugin } from './definitions';

export class GoogleAuthWeb extends WebPlugin implements GoogleAuthPlugin {
  async echo(options: { value: string }): Promise<{ value: string }> {
    console.log('ECHO', options);
    return options;
  }
}
