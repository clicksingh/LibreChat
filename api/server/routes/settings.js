const express = require('express');
const { createToolFavoritesHandlers, createXposePairingHandlers } = require('@librechat/api');
const {
  updateFavoritesController,
  getFavoritesController,
} = require('~/server/controllers/FavoritesController');
const {
  getSkillStatesController,
  updateSkillStatesController,
} = require('~/server/controllers/SkillStatesController');
const { requireJwtAuth } = require('~/server/middleware');
const { getToolFavorites, addToolFavorite, removeToolFavorite } = require('~/models');

const router = express.Router();

const toolFavorites = createToolFavoritesHandlers({
  getToolFavorites,
  addToolFavorite,
  removeToolFavorite,
});

const xposePairing = createXposePairingHandlers();

router.get('/favorites/tools', requireJwtAuth, toolFavorites.listToolFavorites);
router.put('/favorites/tools/:itemType/:itemId', requireJwtAuth, toolFavorites.addToolFavorite);
router.delete(
  '/favorites/tools/:itemType/:itemId',
  requireJwtAuth,
  toolFavorites.removeToolFavorite,
);
router.get('/favorites', requireJwtAuth, getFavoritesController);
router.post('/favorites', requireJwtAuth, updateFavoritesController);
router.get('/skills/active', requireJwtAuth, getSkillStatesController);
router.post('/skills/active', requireJwtAuth, updateSkillStatesController);
router.post('/xpose/devices/claim', requireJwtAuth, xposePairing.claimDevice);

module.exports = router;
