# -*- coding: utf-8 -*-
from . import models
from .config import settings


def read_modifier(db, mod: int = None):
    """
    Read modifier from database
    args:
        db: database session
        mod: modifier id
            None: return all modifier categories
            0: return all modifiers
            else: return modifier with id
    """
    
    if mod == None:
        modifier_catetory = db.query(models.ModifiersClassDB).all()
        return modifier_catetory
        
    elif mod == 0:
        modifier = db.query(models.ModifiersDB).all()
        return modifier
    else: # mod: 1, ..., n
        mod_category = db.query(models.ModifiersClassDB).filter(models.ModifiersClassDB.id == mod).first().modifier
        modifier = db.query(models.ModifiersDB).filter(models.ModifiersDB.modifier == mod_category).all()
        return modifier

def read_presets(db, preset: str = None):
    """
    Read presets from database
    args:
        db: database session
    """
    if preset:
        preset = db.query(models.PresetsDB).filter(models.PresetsDB.name == preset).first()
        return preset
    else:
        presets = db.query(models.PresetsDB).all()
        return presets
