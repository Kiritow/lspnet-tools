import os
import json
from get_logger import get_logger


logger = get_logger('app')


class CacheManager:
    def __init__(self, filepath, readonly=False, sync=True):
        self.cache_path = filepath
        self.readonly = readonly
        self.writeback = sync

        if not os.path.exists(filepath):
            logger.warning('cache file not exists: {}'.format(filepath))
            self.cache = {}
        else:
            with open(filepath) as f:
                content = f.read()
            self.cache = json.loads(content)
    
    def save(self):
        if self.readonly:
            logger.warn('cache mode set to readonly, skip saving')
            return

        content = json.dumps(self.cache, ensure_ascii=False)
        with open(self.cache_path, 'w') as f:
            f.write(content)

    def get(self, key):
        return self.cache.get(key)

    def set(self, key, obj):
        if self.readonly:
            logger.warning('cache mode set to readonly, skip updates')
            return

        self.cache[key] = obj
        if self.writeback:
            self.save()
