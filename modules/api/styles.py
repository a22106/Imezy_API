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

def load_prompts(db, preset: int, user_prompt:str = "", user_negative_prompt:str = ""):
        """
            프리셋 설정
            DB에서 프리셋 설정을 불러와 유저가 입력한 prompt와 db상에서 사전 입력된 base prompt(prompt_b)를 ', '로 합친다.
            negative prompt도 마찬가지

        Args:
            db (Session): database

        Returns:
            prompt_sum, negative_prompt_sum: prompt + prompt_b, negative_prompt + negative_prompt_b
        """    
        preset_db = db.query(models.PresetsDB).filter(models.PresetsDB.id == preset).first()
       
        prompt_b = preset_db.prompt_b if preset_db.prompt_b is not None else ""
        negative_prompt_b = preset_db.negative_prompt_b if preset_db.negative_prompt_b is not None else ""
        
        prompt_sum = ', '.join([user_prompt, prompt_b])
        negative_prompt_sum = ', '.join([user_negative_prompt, negative_prompt_b])
        return prompt_sum, negative_prompt_sum