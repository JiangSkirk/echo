// Global application state
export const state = {
  sessionId: null,
  ws: null,
  currentTab: 'chat',
  selectedModel: '',
  availableModels: [],
  // The model catalog is authoritative only after one successful response.
  // A later refresh error preserves the last successful snapshot so an
  // already-usable conversation is not disabled by a transient failure.
  modelCatalogStatus: 'idle',
  modelCatalogError: null,
  modelCatalogHasSnapshot: false,
  fleetMode: false,
  fleetWS: null,
  fleetAgents: {},
  currentFleetSessionId: null,
  activeStream: null,
  streamGeneration: 0,
  activeFleetRun: null,
  fleetGeneration: 0,
  isStreaming: false,
  currentBubble: null,
  streamBuffer: '',
  pendingAttachments: [],
  currentSkillId: null,
  wizardStep: 1,
  wizardSelectedModel: '',
  // Model/provider state
  discoveredModels: [],
  cloudPresets: [],
  wizardCloudPresets: [],
  // Auth
  // Plaintext credentials are accepted only as one-time function arguments to
  // saveApiKey(). Never hydrate them into module memory from legacy storage.
  apiKey: '',
  // Product capability manifest from /api/capabilities
  capabilities: null,
  // Parent AppShell authority. Never initialize routing from browser storage.
  appShellCapabilities: null,
  activeProduct: '',
};
