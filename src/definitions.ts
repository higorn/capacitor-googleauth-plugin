export interface GoogleAuthPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
}
