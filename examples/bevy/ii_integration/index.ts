import { SignIdentity } from "@icp-sdk/core/agent";
import { Ed25519PublicKey } from "@icp-sdk/core/identity";
import {
  AuthClient,
  type InternetIdentityAuthResponseSuccess,
} from "@dfinity/auth-client";
import { Principal } from "@dfinity/principal";
import { hexToBytes } from "@noble/hashes/utils";

console.log("Starting Internet Identity Login.");

const URL_PARAMS = {
  REDIRECT_URI: "redirectUri",
  PUBKEY: "pubkey",
  IDENTITY_PROVIDER: "identityProvider",
  MAX_TIME_TO_LIVE: "maxTimeToLive",
  ALLOW_PIN_AUTHENTICATION: "allowPinAuthentication",
  DERIVATION_ORIGIN: "derivationOrigin",
  WINDOW_OPENER_FEATURES: "windowOpenerFeatures",
  CUSTOM_VALUES: "customValues",
} as const;

type SuccessPayload = {
  type: "success";
  data: SerializedAuthResponse;
};

type ErrorPayload = { type: "error"; data: string | undefined };

type CallbackPayload = SuccessPayload | ErrorPayload;

type SerializedDelegation = {
  delegation: {
    expiration?: string;
    pubkey: number[];
    targets?: string[];
  };
  signature: number[];
};

type SerializedAuthResponse = {
  delegations: SerializedDelegation[];
  userPublicKey: number[];
  authnMethod: string;
};

async function main() {
  try {
    const params = parseParams();
    const redirectUri = params.redirectUri;
    const authClient = await createAuthClient(params);
    startLogin(authClient, redirectUri);
  } catch (error) {
    console.error("Error:", error);
  }
}

async function createAuthClient(params: Params) {
  const identityProvider = params.identityProvider ?? getIdentityProvider();
  return AuthClient.create({
    identity: params.identity,
    keyType: "Ed25519",
    loginOptions: buildLoginOptions(params, identityProvider),
  });
}

type LoginOptions = {
  identityProvider?: string;
  maxTimeToLive?: bigint;
  allowPinAuthentication?: boolean;
  derivationOrigin?: string;
  windowOpenerFeatures?: string;
  customValues?: Record<string, unknown>;
};

function buildLoginOptions(params: Params, identityProvider?: string): LoginOptions {
  return {
    identityProvider,
    maxTimeToLive: params.maxTimeToLive,
    allowPinAuthentication: params.allowPinAuthentication,
    derivationOrigin: params.derivationOrigin,
    windowOpenerFeatures: params.windowOpenerFeatures,
    customValues: params.customValues,
  };
}

function startLogin(authClient: AuthClient, redirectUri: string) {
  authClient.login({
    onSuccess: (response) => handleSuccess(response, redirectUri),
    onError: (error) => handleFailure(error, redirectUri),
  });
}

function handleSuccess(
  response: InternetIdentityAuthResponseSuccess,
  redirectUri: string,
) {
  sendPostMessage(redirectUri, createSuccessPayload(response));
}

function handleFailure(error: string | undefined, redirectUri: string) {
  sendPostMessage(redirectUri, { type: "error", data: error });
}

function createSuccessPayload(
  response: InternetIdentityAuthResponseSuccess,
): SuccessPayload {
  const serialized = serializeResponse(response);
  return { type: "success", data: serialized };
}

async function sendPostMessage(redirectUri: string, payload: CallbackPayload) {
  try {
    await postToNativeCallback(redirectUri, payload);
    window.close();
  } catch (e) {
    console.error("Failed to send post message, falling back to redirect:", e);
    redirectToCallback(redirectUri, payload);
  }
}

async function postToNativeCallback(redirectUri: string, payload: CallbackPayload) {
  const body = serializePayload(payload);
  await fetch(redirectUri, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body,
  });
}

function redirectToCallback(redirectUri: string, payload: CallbackPayload) {
  const url = new URL(redirectUri);
  url.searchParams.set("payload", encodePayload(payload));
  window.location.href = url.toString();
}

function serializeResponse(
  response: InternetIdentityAuthResponseSuccess,
): SerializedAuthResponse {
  return {
    authnMethod: response.authnMethod,
    userPublicKey: toBytes(response.userPublicKey),
    delegations: response.delegations.map(serializeDelegation),
  };
}

type DelegationPayload = InternetIdentityAuthResponseSuccess["delegations"][number];

function serializeDelegation(delegation: DelegationPayload): SerializedDelegation {
  return {
    signature: toBytes(delegation.signature),
    delegation: {
      expiration: serializeExpiration(delegation.delegation.expiration),
      pubkey: toBytes(delegation.delegation.pubkey),
      targets: serializeTargets(delegation.delegation.targets),
    },
  };
}

function serializeExpiration(expiration: DelegationPayload["delegation"]["expiration"]) {
  return expiration ? expiration.toString() : undefined;
}

function serializeTargets(
  targets: DelegationPayload["delegation"]["targets"],
): string[] | undefined {
  if (!targets) {
    return undefined;
  }

  return targets.map((target) =>
    isPrincipal(target)
      ? target.toText()
      : Principal.fromUint8Array(toUint8Array(target)).toText(),
  );
}

function toBytes(
  array: Uint8Array | ArrayBuffer | ArrayLike<number> | undefined,
): number[] {
  if (!array) {
    return [];
  }
  return Array.from(toUint8Array(array));
}

function isPrincipal(value: unknown): value is Principal {
  return (
    typeof value === "object" &&
    value !== null &&
    "toText" in value &&
    typeof (value as { toText?: unknown }).toText === "function"
  );
}

function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
  }

  return new Uint8Array(value as ArrayLike<number>);
}

function encodePayload(payload: CallbackPayload): string {
  const json = serializePayload(payload);
  const encoded = new TextEncoder().encode(json);
  let binary = "";
  encoded.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function serializePayload(payload: CallbackPayload): string {
  return JSON.stringify(payload, (_key, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  });
}

class IncompleteEd25519KeyIdentity extends SignIdentity {
  private _publicKey: Ed25519PublicKey;

  constructor(publicKey: Ed25519PublicKey) {
    super();
    this._publicKey = publicKey;
  }

  getPublicKey(): Ed25519PublicKey {
    return this._publicKey;
  }

  async sign(_blob: Uint8Array): Promise<Uint8Array & { __signature__: void }> {
    throw new Error("Signing not implemented");
  }
}

type Params = {
  redirectUri: string;
  identity: SignIdentity;
  identityProvider?: string;
  maxTimeToLive?: bigint;
  allowPinAuthentication?: boolean;
  derivationOrigin?: string;
  windowOpenerFeatures?: string;
  customValues?: Record<string, unknown>;
};

function createIdentityFromPubKey(pubKey: string): SignIdentity {
  try {
    return new IncompleteEd25519KeyIdentity(
      Ed25519PublicKey.fromDer(hexToBytes(pubKey)),
    );
  } catch (e) {
    const error = new Error("Invalid public key format");
    renderError(error);
    throw error;
  }
}

/**
 * Parses the query string parameters from the URL.
 */
function parseParams(): Params {
  const url = new URL(window.location.href);
  const params = url.searchParams;

  // Helper function to get optional string parameter
  const getOptionalParam = (key: string): string | undefined => {
    const value = params.get(key);
    return value || undefined;
  };

  // Helper function to get optional boolean parameter
  const getOptionalBooleanParam = (key: string): boolean | undefined => {
    const value = params.get(key);
    return value ? value === "true" : undefined;
  };

  // Helper function to get optional bigint parameter
  const getOptionalBigIntParam = (key: string): bigint | undefined => {
    const value = params.get(key);
    return value ? BigInt(value) : undefined;
  };

  // Helper function to get optional JSON parameter
  const getOptionalJSONParam = (
    key: string,
  ): Record<string, unknown> | undefined => {
    const value = params.get(key);
    if (!value) return undefined;

    try {
      return JSON.parse(value);
    } catch {
      throw new Error(`Invalid JSON format for parameter: ${key}`);
    }
  };

  // Extract required parameters
  const redirectUriParam = params.get(URL_PARAMS.REDIRECT_URI);
  const pubKey = params.get(URL_PARAMS.PUBKEY);

  if (!redirectUriParam || !pubKey) {
    const error = new Error("Missing redirect_uri or pubkey in query string");
    renderError(error);
    throw error;
  }

  const identity = createIdentityFromPubKey(pubKey);

  return {
    redirectUri: decodeURIComponent(redirectUriParam),
    identity,
    identityProvider: getOptionalParam(URL_PARAMS.IDENTITY_PROVIDER),
    maxTimeToLive: getOptionalBigIntParam(URL_PARAMS.MAX_TIME_TO_LIVE),
    allowPinAuthentication: getOptionalBooleanParam(
      URL_PARAMS.ALLOW_PIN_AUTHENTICATION,
    ),
    derivationOrigin: getOptionalParam(URL_PARAMS.DERIVATION_ORIGIN),
    windowOpenerFeatures: getOptionalParam(URL_PARAMS.WINDOW_OPENER_FEATURES),
    customValues: getOptionalJSONParam(URL_PARAMS.CUSTOM_VALUES),
  };
}

window.addEventListener("DOMContentLoaded", () => {
  main();
});

function renderError(error: Error) {
  const errorElement = document.querySelector("#error");
  if (errorElement) {
    errorElement.remove();
  }
  const errorText = document.createElement("p");
  errorText.style.color = "red";
  errorText.id = "error";
  errorText.innerText = error.message;
  document.body.appendChild(errorText);
}

export function getIdentityProvider() {
  let idpProvider;
  // Safeguard against server rendering
  if (typeof window !== "undefined") {
    const isLocal = import.meta.env.DFX_NETWORK !== "ic";
    // Safari does not support localhost subdomains
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    if (isLocal && isSafari) {
      idpProvider = `http://localhost:4943/?canisterId=${import.meta.env.CANISTER_ID_INTERNET_IDENTITY}`;
    } else if (isLocal) {
      idpProvider = `http://${import.meta.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:4943`;
    }
  }
  return idpProvider;
}
