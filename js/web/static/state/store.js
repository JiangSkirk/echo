// Global application state
export const state = {
  sessionId: null,
  ws: null,
  currentTab: 'chat',
  selectedModel: localStorage.getItem('js-selected-model') || '',
  availableModels: [],
  fleetMode: false,
  fleetWS: null,
  fleetAgents: {},
  currentFleetSessionId: null,
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
  apiKey: localStorage.getItem('js-api-key') || '',
  // Product capability manifest from /api/capabilities
  capabilities: null,
  // AppShell dual-backend chrome (ADR 0002)
  activeProduct: localStorage.getItem('js-appshell-active-product') || '',
  personalBaseUrl: localStorage.getItem('js-appshell-personal-url') || 'http://127.0.0.1:8000',
  workBaseUrl: localStorage.getItem('js-appshell-work-url') || 'http://127.0.0.1:8765',
};
