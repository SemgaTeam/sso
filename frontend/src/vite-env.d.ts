/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AUTH_LOGIN_URL: string;
  readonly VITE_AUTH_REGISTER_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
