/**
 * What to do about a finding. The first step is provider-specific (where to
 * revoke), the rest is the same discipline for every leaked credential.
 * Every sentence exists in English and Spanish.
 */

import type { ScanFinding } from "./types";

export type RemediationLang = "en" | "es";

export interface Remediation {
  readonly revoke: string;
  readonly console?: { readonly label: string; readonly href: string };
  readonly steps: readonly string[];
}

type Text = Readonly<Record<RemediationLang, string>>;

interface Playbook {
  readonly match: (finding: ScanFinding) => boolean;
  readonly revoke: Text;
  readonly console?: { readonly label: Text; readonly href: string };
}

const has = (finding: ScanFinding, tag: string): boolean => finding.tags.includes(tag);
const same = (label: string): Text => ({ en: label, es: label });

const PLAYBOOKS: readonly Playbook[] = [
  {
    match: (f) => has(f, "aws"),
    revoke: {
      en: "Deactivate the access key in IAM, create a new one, then delete the old key once nothing uses it.",
      es: "Desactiva la clave de acceso en IAM, crea una nueva y borra la antigua cuando nada la use.",
    },
    console: { label: { en: "AWS IAM credentials", es: "Credenciales de AWS IAM" }, href: "https://console.aws.amazon.com/iam/home#/security_credentials" },
  },
  {
    match: (f) => has(f, "gcp"),
    revoke: {
      en: "Delete or regenerate the key in Google Cloud; for a service account, disable the key and issue a new one.",
      es: "Borra o regenera la clave en Google Cloud; si es una cuenta de servicio, desactiva la clave y emite otra.",
    },
    console: { label: { en: "Google Cloud credentials", es: "Credenciales de Google Cloud" }, href: "https://console.cloud.google.com/apis/credentials" },
  },
  {
    match: (f) => has(f, "entra"),
    revoke: {
      en: "Delete the client secret in the app registration and create a new one with a short expiry.",
      es: "Borra el secreto de cliente en el registro de la app y crea otro con una caducidad corta.",
    },
  },
  {
    match: (f) => has(f, "azure"),
    revoke: {
      en: "Rotate the storage account access key (key1/key2) and move clients to the regenerated one.",
      es: "Rota la clave de acceso de la cuenta de almacenamiento (key1/key2) y pasa los clientes a la regenerada.",
    },
  },
  {
    match: (f) => has(f, "github"),
    revoke: {
      en: "Delete the token in GitHub developer settings and issue a fine-grained token with the least scope it needs.",
      es: "Borra el token en la configuración de desarrollador de GitHub y emite uno de permisos finos con el alcance mínimo.",
    },
    console: { label: { en: "GitHub tokens", es: "Tokens de GitHub" }, href: "https://github.com/settings/tokens" },
  },
  {
    match: (f) => has(f, "gitlab"),
    revoke: {
      en: "Revoke the token in GitLab and create a replacement with a short expiry.",
      es: "Revoca el token en GitLab y crea uno de reemplazo con caducidad corta.",
    },
    console: { label: { en: "GitLab access tokens", es: "Tokens de acceso de GitLab" }, href: "https://gitlab.com/-/user_settings/personal_access_tokens" },
  },
  {
    match: (f) => has(f, "stripe"),
    revoke: {
      en: "Roll the key in the Stripe dashboard; a restricted key with only the permissions you use is safer.",
      es: "Rota la clave en el panel de Stripe; una clave restringida con solo los permisos que usas es más segura.",
    },
    console: { label: { en: "Stripe API keys", es: "Claves de API de Stripe" }, href: "https://dashboard.stripe.com/apikeys" },
  },
  {
    match: (f) => has(f, "braintree"),
    revoke: {
      en: "Revoke the access token in the Braintree control panel and generate a new one.",
      es: "Revoca el token de acceso en el panel de Braintree y genera uno nuevo.",
    },
  },
  {
    match: (f) => has(f, "openai"),
    revoke: {
      en: "Revoke the key in the OpenAI platform and create a new project-scoped key.",
      es: "Revoca la clave en la plataforma de OpenAI y crea una nueva limitada a un proyecto.",
    },
    console: { label: { en: "OpenAI API keys", es: "Claves de API de OpenAI" }, href: "https://platform.openai.com/api-keys" },
  },
  {
    match: (f) => has(f, "anthropic"),
    revoke: {
      en: "Delete the key in the Anthropic Console and create a new one.",
      es: "Borra la clave en la consola de Anthropic y crea una nueva.",
    },
    console: { label: { en: "Anthropic API keys", es: "Claves de API de Anthropic" }, href: "https://console.anthropic.com/settings/keys" },
  },
  {
    match: (f) => has(f, "huggingface"),
    revoke: {
      en: "Invalidate the token in Hugging Face settings and create a new one, read-only if possible.",
      es: "Invalida el token en la configuración de Hugging Face y crea otro, de solo lectura si es posible.",
    },
    console: { label: { en: "Hugging Face tokens", es: "Tokens de Hugging Face" }, href: "https://huggingface.co/settings/tokens" },
  },
  {
    match: (f) => has(f, "slack"),
    revoke: {
      en: "Regenerate the token or webhook URL from the Slack app's configuration page.",
      es: "Regenera el token o la URL del webhook desde la configuración de la app de Slack.",
    },
    console: { label: same("Slack apps"), href: "https://api.slack.com/apps" },
  },
  {
    match: (f) => has(f, "discord"),
    revoke: {
      en: "Reset the bot token, or delete and recreate the webhook, in the Discord developer portal or channel settings.",
      es: "Restablece el token del bot, o borra y vuelve a crear el webhook, en el portal de desarrolladores o en la configuración del canal.",
    },
    console: { label: { en: "Discord developer portal", es: "Portal de desarrolladores de Discord" }, href: "https://discord.com/developers/applications" },
  },
  {
    match: (f) => has(f, "twilio"),
    revoke: {
      en: "Delete the API key in the Twilio console (or rotate the auth token) and create a new one.",
      es: "Borra la clave de API en la consola de Twilio (o rota el auth token) y crea una nueva.",
    },
  },
  {
    match: (f) => has(f, "sendgrid"),
    revoke: {
      en: "Delete the API key in SendGrid settings and create a new one with restricted access.",
      es: "Borra la clave en la configuración de SendGrid y crea otra con acceso restringido.",
    },
    console: { label: { en: "SendGrid API keys", es: "Claves de API de SendGrid" }, href: "https://app.sendgrid.com/settings/api_keys" },
  },
  {
    match: (f) => has(f, "digitalocean"),
    revoke: {
      en: "Delete the personal access token in DigitalOcean and generate a new one.",
      es: "Borra el token de acceso personal en DigitalOcean y genera uno nuevo.",
    },
    console: { label: { en: "DigitalOcean tokens", es: "Tokens de DigitalOcean" }, href: "https://cloud.digitalocean.com/account/api/tokens" },
  },
  {
    match: (f) => has(f, "supabase"),
    revoke: {
      en: "Revoke the access token in your Supabase account settings and create a new one.",
      es: "Revoca el token de acceso en la configuración de tu cuenta de Supabase y crea uno nuevo.",
    },
    console: { label: { en: "Supabase access tokens", es: "Tokens de acceso de Supabase" }, href: "https://supabase.com/dashboard/account/tokens" },
  },
  {
    match: (f) => has(f, "cloudflare"),
    revoke: {
      en: "Roll or delete the API token in the Cloudflare dashboard and scope the new one to the zones it needs.",
      es: "Rota o borra el token de API en el panel de Cloudflare y limita el nuevo a las zonas que necesita.",
    },
    console: { label: { en: "Cloudflare API tokens", es: "Tokens de API de Cloudflare" }, href: "https://dash.cloudflare.com/profile/api-tokens" },
  },
  {
    match: (f) => has(f, "vercel"),
    revoke: {
      en: "Delete the token in your Vercel account settings and create a new one with an expiry.",
      es: "Borra el token en la configuración de tu cuenta de Vercel y crea otro con caducidad.",
    },
    console: { label: { en: "Vercel tokens", es: "Tokens de Vercel" }, href: "https://vercel.com/account/tokens" },
  },
  {
    match: (f) => has(f, "datadog"),
    revoke: {
      en: "Revoke the key in Datadog Organization Settings and create a new one.",
      es: "Revoca la clave en la configuración de la organización de Datadog y crea una nueva.",
    },
  },
  {
    match: (f) => has(f, "telegram"),
    revoke: {
      en: "Send /revoke to @BotFather for this bot to invalidate the token and get a new one.",
      es: "Envía /revoke a @BotFather para este bot: invalida el token y te da uno nuevo.",
    },
  },
  {
    match: (f) => has(f, "pypi"),
    revoke: {
      en: "Remove the API token in your PyPI account settings; prefer trusted publishing from CI.",
      es: "Elimina el token de API en tu cuenta de PyPI; mejor publica desde CI con trusted publishing.",
    },
    console: { label: { en: "PyPI account", es: "Cuenta de PyPI" }, href: "https://pypi.org/manage/account/" },
  },
  {
    match: (f) => has(f, "npm"),
    revoke: {
      en: "Revoke the token in your npm account's access tokens page and publish with a granular token.",
      es: "Revoca el token en la página de tokens de tu cuenta de npm y publica con un token granular.",
    },
  },
  {
    match: (f) => has(f, "database") || has(f, "queue") || has(f, "basic-auth"),
    revoke: {
      en: "Change this user's password on the server, update the connection string where it is configured, and check the logs for unknown clients.",
      es: "Cambia la contraseña de este usuario en el servidor, actualiza la cadena de conexión donde esté configurada y revisa los logs en busca de clientes desconocidos.",
    },
  },
  {
    match: (f) => has(f, "crypto"),
    revoke: {
      en: "Generate a new key pair, replace the public key wherever it is trusted (authorized_keys, CA, deploy keys) and remove the old one.",
      es: "Genera un par de claves nuevo, reemplaza la clave pública donde se confíe en ella (authorized_keys, CA, deploy keys) y elimina la antigua.",
    },
  },
  {
    match: (f) => has(f, "jwt"),
    revoke: {
      en: "If this token is live, rotate the signing secret so every issued token becomes invalid, then let clients sign in again.",
      es: "Si el token está vigente, rota el secreto de firma para invalidar todos los tokens emitidos y deja que los clientes vuelvan a iniciar sesión.",
    },
  },
  {
    match: (f) => has(f, "vault") || has(f, "terraform"),
    revoke: {
      en: "Revoke the token (vault token revoke, or the Terraform Cloud user settings) and issue one with a short TTL.",
      es: "Revoca el token (vault token revoke, o la configuración de usuario de Terraform Cloud) y emite uno con un TTL corto.",
    },
  },
];

const GENERIC: Text = {
  en: "Treat it as compromised: rotate it with whoever issued it, even if the repository is private.",
  es: "Trátalo como comprometido: rótalo con quien lo emitió, aunque el repositorio sea privado.",
};

const STEPS: Readonly<Record<string, Text>> = {
  env: {
    en: "Load it from the environment or a secret manager instead of the file.",
    es: "Cárgalo desde el entorno o un gestor de secretos en lugar del archivo.",
  },
  history: {
    en: "If it was ever committed, rewriting history (git filter-repo) hides it but does not un-leak it: rotate first.",
    es: "Si alguna vez se hizo commit, reescribir el historial (git filter-repo) lo oculta pero no deshace la fuga: rota primero.",
  },
  audit: {
    en: "Check the provider's audit log for use you don't recognise since the leak.",
    es: "Revisa el registro de auditoría del proveedor en busca de usos que no reconozcas desde la fuga.",
  },
  encoded: {
    en: "Base64 is an encoding, not encryption: anyone with the file can read this value.",
    es: "Base64 es una codificación, no un cifrado: cualquiera con el archivo puede leer este valor.",
  },
  removed: {
    en: "Deleting the line in this diff does not remove it from git history or from forks and clones: rotate it anyway.",
    es: "Borrar la línea en este diff no la saca del historial de git ni de forks y clones: rótala de todos modos.",
  },
};

export function remediationFor(finding: ScanFinding, lang: RemediationLang = "en"): Remediation {
  if (finding.tags.includes("informational")) {
    return lang === "es"
      ? {
          revoke: "Las claves publicables están pensadas para el cliente, así que esto no es una fuga por sí solo.",
          steps: ["Confirma que es la clave publicable y no una clave secreta o restringida."],
        }
      : {
          revoke: "Publishable keys are meant for clients, so this is not a leak by itself.",
          steps: ["Confirm it is the publishable key and not a secret or restricted key."],
        };
  }
  const playbook = PLAYBOOKS.find((entry) => entry.match(finding));
  const steps: string[] = [];
  if (finding.tags.includes("diff-removed")) steps.push(STEPS.removed?.[lang] ?? "");
  if (finding.tags.includes("encoded")) steps.push(STEPS.encoded?.[lang] ?? "");
  steps.push(STEPS.env?.[lang] ?? "", STEPS.history?.[lang] ?? "", STEPS.audit?.[lang] ?? "");
  const revoke = (playbook?.revoke ?? GENERIC)[lang];
  return playbook?.console !== undefined
    ? { revoke, console: { label: playbook.console.label[lang], href: playbook.console.href }, steps }
    : { revoke, steps };
}
