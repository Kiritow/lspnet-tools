import os
import json

from common.utils import logger


class CacheManager:
    def __init__(self, filepath='', readonly=False, writeback=True, load=True):
        self.cache_path = filepath
        self.readonly = readonly
        self.writeback = writeback

        self.cache = {}
        if not load:
            return

        if filepath and not os.path.exists(filepath):
            logger.warning('cache file does not exist: {}'.format(filepath))
        elif filepath:
            logger.info('loading cache from {}...'.format(filepath))

            with open(filepath) as f:
                content = f.read()
            self.cache = json.loads(content)

    def save(self):
        if self.readonly:
            logger.warn('cache mode set to readonly, skip saving')
            return

        content = json.dumps(self.cache, ensure_ascii=False)

        if self.cache_path:
            logger.info('saving cache to {}...'.format(self.cache_path))
            with open(self.cache_path, 'w') as f:
                f.write(content)

    def get(self, key, default=None):
        return self.cache.get(key, default)

    def set(self, key, obj):
        if self.readonly:
            logger.warning('cache mode set to readonly, skip updates')
            return

        self.cache[key] = obj
        if self.writeback:
            self.save()
