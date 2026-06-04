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
};
