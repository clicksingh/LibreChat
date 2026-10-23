'use strict';
let config = null;

function setOpenIdConfig(value) {
  config = value ?? null;
  return config;
}

function getOpenIdConfig() {
  if (!config) {
    throw new Error('OpenID client is not initialized. Please call setupOpenId first.');
  }
  return config;
}

function clearOpenIdConfig() {
  config = null;
}

module.exports = { setOpenIdConfig, getOpenIdConfig, clearOpenIdConfig };
